/* 
 *  Unix SMB/CIFS implementation.
 *  RPC Pipe client / server routines
 *  Largely rewritten by Jeremy Allison		    2005.
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
#include "librpc/gen_ndr/cli_epmapper.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_RPC_CLI

/*******************************************************************
interface/version dce/rpc pipe identification
********************************************************************/

#define PIPE_SRVSVC   "\\PIPE\\srvsvc"
#define PIPE_SAMR     "\\PIPE\\samr"
#define PIPE_WINREG   "\\PIPE\\winreg"
#define PIPE_WKSSVC   "\\PIPE\\wkssvc"
#define PIPE_NETLOGON "\\PIPE\\NETLOGON"
#define PIPE_NTLSA    "\\PIPE\\ntlsa"
#define PIPE_NTSVCS   "\\PIPE\\ntsvcs"
#define PIPE_LSASS    "\\PIPE\\lsass"
#define PIPE_LSARPC   "\\PIPE\\lsarpc"
#define PIPE_SPOOLSS  "\\PIPE\\spoolss"
#define PIPE_NETDFS   "\\PIPE\\netdfs"
#define PIPE_ECHO     "\\PIPE\\rpcecho"
#define PIPE_SHUTDOWN "\\PIPE\\initshutdown"
#define PIPE_EPM      "\\PIPE\\epmapper"
#define PIPE_SVCCTL   "\\PIPE\\svcctl"
#define PIPE_EVENTLOG "\\PIPE\\eventlog"
#define PIPE_EPMAPPER "\\PIPE\\epmapper"
#define PIPE_DRSUAPI  "\\PIPE\\drsuapi"

/*
 * IMPORTANT!!  If you update this structure, make sure to
 * update the index #defines in smb.h.
 */

static const struct pipe_id_info {
	/* the names appear not to matter: the syntaxes _do_ matter */

	const char *client_pipe;
	const RPC_IFACE *abstr_syntax; /* this one is the abstract syntax id */
} pipe_names [] =
{
	{ PIPE_LSARPC,		&ndr_table_lsarpc.syntax_id },
	{ PIPE_LSARPC,		&ndr_table_dssetup.syntax_id },
	{ PIPE_SAMR,		&ndr_table_samr.syntax_id },
	{ PIPE_NETLOGON,	&ndr_table_netlogon.syntax_id },
	{ PIPE_SRVSVC,		&ndr_table_srvsvc.syntax_id },
	{ PIPE_WKSSVC,		&ndr_table_wkssvc.syntax_id },
	{ PIPE_WINREG,		&ndr_table_winreg.syntax_id },
	{ PIPE_SPOOLSS,		&syntax_spoolss },
	{ PIPE_NETDFS,		&ndr_table_netdfs.syntax_id },
	{ PIPE_ECHO,		&ndr_table_rpcecho.syntax_id },
	{ PIPE_SHUTDOWN,	&ndr_table_initshutdown.syntax_id },
	{ PIPE_SVCCTL,		&ndr_table_svcctl.syntax_id },
	{ PIPE_EVENTLOG,	&ndr_table_eventlog.syntax_id },
	{ PIPE_NTSVCS,		&ndr_table_ntsvcs.syntax_id },
	{ PIPE_EPMAPPER,	&ndr_table_epmapper.syntax_id },
	{ PIPE_DRSUAPI,		&ndr_table_drsuapi.syntax_id },
	{ NULL, NULL }
};

/****************************************************************************
 Return the pipe name from the interface.
 ****************************************************************************/

const char *cli_get_pipe_name_from_iface(TALLOC_CTX *mem_ctx,
					 struct cli_state *cli,
					 const struct ndr_syntax_id *interface)
{
	int i;
	for (i = 0; pipe_names[i].client_pipe; i++) {
		if (ndr_syntax_id_equal(pipe_names[i].abstr_syntax,
					interface)) {
			return &pipe_names[i].client_pipe[5];
		}
	}

	/*
	 * Here we should ask \\epmapper, but for now our code is only
	 * interested in the known pipes mentioned in pipe_names[]
	 */

	return NULL;
}

/********************************************************************
 Map internal value to wire value.
 ********************************************************************/

static int map_pipe_auth_type_to_rpc_auth_type(enum pipe_auth_type auth_type)
{
	switch (auth_type) {

	case PIPE_AUTH_TYPE_NONE:
		return RPC_ANONYMOUS_AUTH_TYPE;

	case PIPE_AUTH_TYPE_NTLMSSP:
		return RPC_NTLMSSP_AUTH_TYPE;

	case PIPE_AUTH_TYPE_SPNEGO_NTLMSSP:
	case PIPE_AUTH_TYPE_SPNEGO_KRB5:
		return RPC_SPNEGO_AUTH_TYPE;

	case PIPE_AUTH_TYPE_SCHANNEL:
		return RPC_SCHANNEL_AUTH_TYPE;

	case PIPE_AUTH_TYPE_KRB5:
		return RPC_KRB5_AUTH_TYPE;

	default:
		DEBUG(0,("map_pipe_auth_type_to_rpc_type: unknown pipe "
			"auth type %u\n",
			(unsigned int)auth_type ));
		break;
	}
	return -1;
}

/********************************************************************
 Pipe description for a DEBUG
 ********************************************************************/
static char *rpccli_pipe_txt(TALLOC_CTX *mem_ctx, struct rpc_pipe_client *cli)
{
	char *result;

	switch (cli->transport_type) {
	case NCACN_NP:
		result = talloc_asprintf(mem_ctx, "host %s, pipe %s, "
					 "fnum 0x%x",
					 cli->desthost,
					 cli->trans.np.pipe_name,
					 (unsigned int)(cli->trans.np.fnum));
		break;
	case NCACN_IP_TCP:
	case NCACN_UNIX_STREAM:
		result = talloc_asprintf(mem_ctx, "host %s, fd %d",
					 cli->desthost, cli->trans.sock.fd);
		break;
	default:
		result = talloc_asprintf(mem_ctx, "host %s", cli->desthost);
		break;
	}
	SMB_ASSERT(result != NULL);
	return result;
}

/********************************************************************
 Rpc pipe call id.
 ********************************************************************/

static uint32 get_rpc_call_id(void)
{
	static uint32 call_id = 0;
	return ++call_id;
}

/*******************************************************************
 Read from a RPC named pipe
 ********************************************************************/
static NTSTATUS rpc_read_np(struct cli_state *cli, const char *pipe_name,
			    int fnum, char *buf, off_t offset, size_t size,
			    ssize_t *pnum_read)
{
       ssize_t num_read;

       num_read = cli_read(cli, fnum, buf, offset, size);

       DEBUG(5,("rpc_read_np: num_read = %d, read offset: %u, to read: %u\n",
		(int)num_read, (unsigned int)offset, (unsigned int)size));

       /*
	* A dos error of ERRDOS/ERRmoredata is not an error.
	*/
       if (cli_is_dos_error(cli)) {
	       uint32 ecode;
	       uint8 eclass;
	       cli_dos_error(cli, &eclass, &ecode);
	       if (eclass != ERRDOS && ecode != ERRmoredata) {
		       DEBUG(0,("rpc_read: DOS Error %d/%u (%s) in cli_read "
				"on fnum 0x%x\n", eclass, (unsigned int)ecode,
				cli_errstr(cli), fnum));
		       return dos_to_ntstatus(eclass, ecode);
	       }
       }

       /*
	* Likewise for NT_STATUS_BUFFER_TOO_SMALL
	*/
       if (cli_is_nt_error(cli)) {
	       if (!NT_STATUS_EQUAL(cli_nt_error(cli),
				    NT_STATUS_BUFFER_TOO_SMALL)) {
		       DEBUG(0,("rpc_read: Error (%s) in cli_read on fnum "
				"0x%x\n", nt_errstr(cli_nt_error(cli)), fnum));
		       return cli_nt_error(cli);
	       }
       }

       if (num_read == -1) {
	       DEBUG(0,("rpc_read: Error - cli_read on fnum 0x%x returned "
			"-1\n", fnum));
	       return cli_get_nt_error(cli);
       }

       *pnum_read = num_read;
       return NT_STATUS_OK;
}


/*******************************************************************
 Use SMBreadX to get rest of one fragment's worth of rpc data.
 Will expand the current_pdu struct to the correct size.
 ********************************************************************/

static NTSTATUS rpc_read(struct rpc_pipe_client *cli,
			prs_struct *current_pdu,
			uint32 data_to_read,
			uint32 *current_pdu_offset)
{
	size_t size = (size_t)cli->max_recv_frag;
	uint32 stream_offset = 0;
	ssize_t num_read = 0;
	char *pdata;
	ssize_t extra_data_size = ((ssize_t)*current_pdu_offset) + ((ssize_t)data_to_read) - (ssize_t)prs_data_size(current_pdu);

	DEBUG(5,("rpc_read: data_to_read: %u current_pdu offset: %u extra_data_size: %d\n",
		(unsigned int)data_to_read, (unsigned int)*current_pdu_offset, (int)extra_data_size ));

	/*
	 * Grow the buffer if needed to accommodate the data to be read.
	 */

	if (extra_data_size > 0) {
		if(!prs_force_grow(current_pdu, (uint32)extra_data_size)) {
			DEBUG(0,("rpc_read: Failed to grow parse struct by %d bytes.\n", (int)extra_data_size ));
			return NT_STATUS_NO_MEMORY;
		}
		DEBUG(5,("rpc_read: grew buffer by %d bytes to %u\n", (int)extra_data_size, prs_data_size(current_pdu) ));
	}

	pdata = prs_data_p(current_pdu) + *current_pdu_offset;

	do {
		NTSTATUS status;

		/* read data using SMBreadX */
		if (size > (size_t)data_to_read) {
			size = (size_t)data_to_read;
		}

		switch (cli->transport_type) {
		case NCACN_NP:
			status = rpc_read_np(cli->trans.np.cli,
					     cli->trans.np.pipe_name,
					     cli->trans.np.fnum, pdata,
					     (off_t)stream_offset, size,
					     &num_read);
			break;
		case NCACN_IP_TCP:
		case NCACN_UNIX_STREAM:
			status = NT_STATUS_OK;
			num_read = sys_read(cli->trans.sock.fd, pdata, size);
			if (num_read == -1) {
				status = map_nt_error_from_unix(errno);
			}
			if (num_read == 0) {
				status = NT_STATUS_END_OF_FILE;
			}
			break;
		default:
			DEBUG(0, ("unknown transport type %d\n",
				  cli->transport_type));
			return NT_STATUS_INTERNAL_ERROR;
		}

		data_to_read -= num_read;
		stream_offset += num_read;
		pdata += num_read;

	} while (num_read > 0 && data_to_read > 0);
	/* && err == (0x80000000 | STATUS_BUFFER_OVERFLOW)); */

	/*
	 * Update the current offset into current_pdu by the amount read.
	 */
	*current_pdu_offset += stream_offset;
	return NT_STATUS_OK;
}

/****************************************************************************
 Try and get a PDU's worth of data from current_pdu. If not, then read more
 from the wire.
 ****************************************************************************/

static NTSTATUS cli_pipe_get_current_pdu(struct rpc_pipe_client *cli, RPC_HDR *prhdr, prs_struct *current_pdu)
{
	NTSTATUS ret = NT_STATUS_OK;
	uint32 current_pdu_len = prs_data_size(current_pdu);

	/* Ensure we have at least RPC_HEADER_LEN worth of data to parse. */
	if (current_pdu_len < RPC_HEADER_LEN) {
		/* rpc_read expands the current_pdu struct as neccessary. */
		ret = rpc_read(cli, current_pdu, RPC_HEADER_LEN - current_pdu_len, &current_pdu_len);
		if (!NT_STATUS_IS_OK(ret)) {
			return ret;
		}
	}

	/* This next call sets the endian bit correctly in current_pdu. */
	/* We will propagate this to rbuf later. */
	if(!smb_io_rpc_hdr("rpc_hdr   ", prhdr, current_pdu, 0)) {
		DEBUG(0,("cli_pipe_get_current_pdu: Failed to unmarshall RPC_HDR.\n"));
		return NT_STATUS_BUFFER_TOO_SMALL;
	}

	/* Ensure we have frag_len bytes of data. */
	if (current_pdu_len < prhdr->frag_len) {
		/* rpc_read expands the current_pdu struct as neccessary. */
		ret = rpc_read(cli, current_pdu, (uint32)prhdr->frag_len - current_pdu_len, &current_pdu_len);
		if (!NT_STATUS_IS_OK(ret)) {
			return ret;
		}
	}

	if (current_pdu_len < prhdr->frag_len) {
		return NT_STATUS_BUFFER_TOO_SMALL;
	}

	return NT_STATUS_OK;
}

/****************************************************************************
 NTLMSSP specific sign/seal.
 Virtually identical to rpc_server/srv_pipe.c:api_pipe_ntlmssp_auth_process.
 In fact I should probably abstract these into identical pieces of code... JRA.
 ****************************************************************************/

static NTSTATUS cli_pipe_verify_ntlmssp(struct rpc_pipe_client *cli, RPC_HDR *prhdr,
				prs_struct *current_pdu,
				uint8 *p_ss_padding_len)
{
	RPC_HDR_AUTH auth_info;
	uint32 save_offset = prs_offset(current_pdu);
	uint32 auth_len = prhdr->auth_len;
	NTLMSSP_STATE *ntlmssp_state = cli->auth->a_u.ntlmssp_state;
	unsigned char *data = NULL;
	size_t data_len;
	unsigned char *full_packet_data = NULL;
	size_t full_packet_data_len;
	DATA_BLOB auth_blob;
	NTSTATUS status;

	if (cli->auth->auth_level == PIPE_AUTH_LEVEL_NONE
	    || cli->auth->auth_level == PIPE_AUTH_LEVEL_CONNECT) {
		return NT_STATUS_OK;
	}

	if (!ntlmssp_state) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	/* Ensure there's enough data for an authenticated response. */
	if ((auth_len > RPC_MAX_SIGN_SIZE) ||
			(RPC_HEADER_LEN + RPC_HDR_RESP_LEN + RPC_HDR_AUTH_LEN + auth_len > prhdr->frag_len)) {
		DEBUG(0,("cli_pipe_verify_ntlmssp: auth_len %u is too large.\n",
			(unsigned int)auth_len ));
		return NT_STATUS_BUFFER_TOO_SMALL;
	}

	/*
	 * We need the full packet data + length (minus auth stuff) as well as the packet data + length
	 * after the RPC header.
	 * We need to pass in the full packet (minus auth len) to the NTLMSSP sign and check seal
	 * functions as NTLMv2 checks the rpc headers also.
	 */

	data = (unsigned char *)(prs_data_p(current_pdu) + RPC_HEADER_LEN + RPC_HDR_RESP_LEN);
	data_len = (size_t)(prhdr->frag_len - RPC_HEADER_LEN - RPC_HDR_RESP_LEN - RPC_HDR_AUTH_LEN - auth_len);

	full_packet_data = (unsigned char *)prs_data_p(current_pdu);
	full_packet_data_len = prhdr->frag_len - auth_len;

	/* Pull the auth header and the following data into a blob. */
	if(!prs_set_offset(current_pdu, RPC_HEADER_LEN + RPC_HDR_RESP_LEN + data_len)) {
		DEBUG(0,("cli_pipe_verify_ntlmssp: cannot move offset to %u.\n",
			(unsigned int)RPC_HEADER_LEN + (unsigned int)RPC_HDR_RESP_LEN + (unsigned int)data_len ));
		return NT_STATUS_BUFFER_TOO_SMALL;
	}

	if(!smb_io_rpc_hdr_auth("hdr_auth", &auth_info, current_pdu, 0)) {
		DEBUG(0,("cli_pipe_verify_ntlmssp: failed to unmarshall RPC_HDR_AUTH.\n"));
		return NT_STATUS_BUFFER_TOO_SMALL;
	}

	auth_blob.data = (unsigned char *)prs_data_p(current_pdu) + prs_offset(current_pdu);
	auth_blob.length = auth_len;

	switch (cli->auth->auth_level) {
		case PIPE_AUTH_LEVEL_PRIVACY:
			/* Data is encrypted. */
			status = ntlmssp_unseal_packet(ntlmssp_state,
							data, data_len,
							full_packet_data,
							full_packet_data_len,
							&auth_blob);
			if (!NT_STATUS_IS_OK(status)) {
				DEBUG(0,("cli_pipe_verify_ntlmssp: failed to unseal "
					"packet from %s. Error was %s.\n",
					rpccli_pipe_txt(debug_ctx(), cli),
					nt_errstr(status) ));
				return status;
			}
			break;
		case PIPE_AUTH_LEVEL_INTEGRITY:
			/* Data is signed. */
			status = ntlmssp_check_packet(ntlmssp_state,
							data, data_len,
							full_packet_data,
							full_packet_data_len,
							&auth_blob);
			if (!NT_STATUS_IS_OK(status)) {
				DEBUG(0,("cli_pipe_verify_ntlmssp: check signing failed on "
					"packet from %s. Error was %s.\n",
					rpccli_pipe_txt(debug_ctx(), cli),
					nt_errstr(status) ));
				return status;
			}
			break;
		default:
			DEBUG(0, ("cli_pipe_verify_ntlmssp: unknown internal "
				  "auth level %d\n", cli->auth->auth_level));
			return NT_STATUS_INVALID_INFO_CLASS;
	}

	/*
	 * Return the current pointer to the data offset.
	 */

	if(!prs_set_offset(current_pdu, save_offset)) {
		DEBUG(0,("api_pipe_auth_process: failed to set offset back to %u\n",
			(unsigned int)save_offset ));
		return NT_STATUS_BUFFER_TOO_SMALL;
	}

	/*
	 * Remember the padding length. We must remove it from the real data
	 * stream once the sign/seal is done.
	 */

	*p_ss_padding_len = auth_info.auth_pad_len;

	return NT_STATUS_OK;
}

/****************************************************************************
 schannel specific sign/seal.
 ****************************************************************************/

static NTSTATUS cli_pipe_verify_schannel(struct rpc_pipe_client *cli, RPC_HDR *prhdr,
				prs_struct *current_pdu,
				uint8 *p_ss_padding_len)
{
	RPC_HDR_AUTH auth_info;
	RPC_AUTH_SCHANNEL_CHK schannel_chk;
	uint32 auth_len = prhdr->auth_len;
	uint32 save_offset = prs_offset(current_pdu);
	struct schannel_auth_struct *schannel_auth =
		cli->auth->a_u.schannel_auth;
	uint32 data_len;

	if (cli->auth->auth_level == PIPE_AUTH_LEVEL_NONE
	    || cli->auth->auth_level == PIPE_AUTH_LEVEL_CONNECT) {
		return NT_STATUS_OK;
	}

	if (auth_len != RPC_AUTH_SCHANNEL_SIGN_OR_SEAL_CHK_LEN) {
		DEBUG(0,("cli_pipe_verify_schannel: auth_len %u.\n", (unsigned int)auth_len ));
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (!schannel_auth) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	/* Ensure there's enough data for an authenticated response. */
	if ((auth_len > RPC_MAX_SIGN_SIZE) ||
			(RPC_HEADER_LEN + RPC_HDR_RESP_LEN + RPC_HDR_AUTH_LEN + auth_len > prhdr->frag_len)) {
		DEBUG(0,("cli_pipe_verify_schannel: auth_len %u is too large.\n",
			(unsigned int)auth_len ));
		return NT_STATUS_INVALID_PARAMETER;
	}

	data_len = prhdr->frag_len - RPC_HEADER_LEN - RPC_HDR_RESP_LEN - RPC_HDR_AUTH_LEN - auth_len;

	if(!prs_set_offset(current_pdu, RPC_HEADER_LEN + RPC_HDR_RESP_LEN + data_len)) {
		DEBUG(0,("cli_pipe_verify_schannel: cannot move offset to %u.\n",
			(unsigned int)RPC_HEADER_LEN + RPC_HDR_RESP_LEN + data_len ));
		return NT_STATUS_BUFFER_TOO_SMALL;
	}

	if(!smb_io_rpc_hdr_auth("hdr_auth", &auth_info, current_pdu, 0)) {
		DEBUG(0,("cli_pipe_verify_schannel: failed to unmarshall RPC_HDR_AUTH.\n"));
		return NT_STATUS_BUFFER_TOO_SMALL;
	}

	if (auth_info.auth_type != RPC_SCHANNEL_AUTH_TYPE) {
		DEBUG(0,("cli_pipe_verify_schannel: Invalid auth info %d on schannel\n",
			auth_info.auth_type));
		return NT_STATUS_BUFFER_TOO_SMALL;
	}

	if(!smb_io_rpc_auth_schannel_chk("", RPC_AUTH_SCHANNEL_SIGN_OR_SEAL_CHK_LEN,
				&schannel_chk, current_pdu, 0)) {
		DEBUG(0,("cli_pipe_verify_schannel: failed to unmarshal RPC_AUTH_SCHANNEL_CHK.\n"));
		return NT_STATUS_BUFFER_TOO_SMALL;
	}

	if (!schannel_decode(schannel_auth,
			cli->auth->auth_level,
			SENDER_IS_ACCEPTOR,
			&schannel_chk,
			prs_data_p(current_pdu)+RPC_HEADER_LEN+RPC_HDR_RESP_LEN,
			data_len)) {
		DEBUG(3,("cli_pipe_verify_schannel: failed to decode PDU "
				"Connection to %s.\n",
				rpccli_pipe_txt(debug_ctx(), cli)));
		return NT_STATUS_INVALID_PARAMETER;
	}

	/* The sequence number gets incremented on both send and receive. */
	schannel_auth->seq_num++;

	/*
	 * Return the current pointer to the data offset.
	 */

	if(!prs_set_offset(current_pdu, save_offset)) {
		DEBUG(0,("api_pipe_auth_process: failed to set offset back to %u\n",
			(unsigned int)save_offset ));
		return NT_STATUS_BUFFER_TOO_SMALL;
	}

	/*
	 * Remember the padding length. We must remove it from the real data
	 * stream once the sign/seal is done.
	 */

	*p_ss_padding_len = auth_info.auth_pad_len;

	return NT_STATUS_OK;
}

/****************************************************************************
 Do the authentication checks on an incoming pdu. Check sign and unseal etc.
 ****************************************************************************/

static NTSTATUS cli_pipe_validate_rpc_response(struct rpc_pipe_client *cli, RPC_HDR *prhdr,
				prs_struct *current_pdu,
				uint8 *p_ss_padding_len)
{
	NTSTATUS ret = NT_STATUS_OK;

	/* Paranioa checks for auth_len. */
	if (prhdr->auth_len) {
		if (prhdr->auth_len > prhdr->frag_len) {
			return NT_STATUS_INVALID_PARAMETER;
		}

		if (prhdr->auth_len + (unsigned int)RPC_HDR_AUTH_LEN < prhdr->auth_len ||
				prhdr->auth_len + (unsigned int)RPC_HDR_AUTH_LEN < (unsigned int)RPC_HDR_AUTH_LEN) {
			/* Integer wrap attempt. */
			return NT_STATUS_INVALID_PARAMETER;
		}
	}

	/*
	 * Now we have a complete RPC request PDU fragment, try and verify any auth data.
	 */

	switch(cli->auth->auth_type) {
		case PIPE_AUTH_TYPE_NONE:
			if (prhdr->auth_len) {
				DEBUG(3, ("cli_pipe_validate_rpc_response: "
					  "Connection to %s - got non-zero "
					  "auth len %u.\n",
					rpccli_pipe_txt(debug_ctx(), cli),
					(unsigned int)prhdr->auth_len ));
				return NT_STATUS_INVALID_PARAMETER;
			}
			break;

		case PIPE_AUTH_TYPE_NTLMSSP:
		case PIPE_AUTH_TYPE_SPNEGO_NTLMSSP:
			ret = cli_pipe_verify_ntlmssp(cli, prhdr, current_pdu, p_ss_padding_len);
			if (!NT_STATUS_IS_OK(ret)) {
				return ret;
			}
			break;

		case PIPE_AUTH_TYPE_SCHANNEL:
			ret = cli_pipe_verify_schannel(cli, prhdr, current_pdu, p_ss_padding_len);
			if (!NT_STATUS_IS_OK(ret)) {
				return ret;
			}
			break;

		case PIPE_AUTH_TYPE_KRB5:
		case PIPE_AUTH_TYPE_SPNEGO_KRB5:
		default:
			DEBUG(3, ("cli_pipe_validate_rpc_response: Connection "
				  "to %s - unknown internal auth type %u.\n",
				  rpccli_pipe_txt(debug_ctx(), cli),
				  cli->auth->auth_type ));
			return NT_STATUS_INVALID_INFO_CLASS;
	}

	return NT_STATUS_OK;
}

/****************************************************************************
 Do basic authentication checks on an incoming pdu.
 ****************************************************************************/

static NTSTATUS cli_pipe_validate_current_pdu(struct rpc_pipe_client *cli, RPC_HDR *prhdr,
			prs_struct *current_pdu,
			uint8 expected_pkt_type,
			char **ppdata,
			uint32 *pdata_len,
			prs_struct *return_data)
{

	NTSTATUS ret = NT_STATUS_OK;
	uint32 current_pdu_len = prs_data_size(current_pdu);

	if (current_pdu_len != prhdr->frag_len) {
		DEBUG(5,("cli_pipe_validate_current_pdu: incorrect pdu length %u, expected %u\n",
			(unsigned int)current_pdu_len, (unsigned int)prhdr->frag_len ));
		return NT_STATUS_INVALID_PARAMETER;
	}

	/*
	 * Point the return values at the real data including the RPC
	 * header. Just in case the caller wants it.
	 */
	*ppdata = prs_data_p(current_pdu);
	*pdata_len = current_pdu_len;

	/* Ensure we have the correct type. */
	switch (prhdr->pkt_type) {
		case RPC_ALTCONTRESP:
		case RPC_BINDACK:

			/* Alter context and bind ack share the same packet definitions. */
			break;


		case RPC_RESPONSE:
		{
			RPC_HDR_RESP rhdr_resp;
			uint8 ss_padding_len = 0;

			if(!smb_io_rpc_hdr_resp("rpc_hdr_resp", &rhdr_resp, current_pdu, 0)) {
				DEBUG(5,("cli_pipe_validate_current_pdu: failed to unmarshal RPC_HDR_RESP.\n"));
				return NT_STATUS_BUFFER_TOO_SMALL;
			}

			/* Here's where we deal with incoming sign/seal. */
			ret = cli_pipe_validate_rpc_response(cli, prhdr,
					current_pdu, &ss_padding_len);
			if (!NT_STATUS_IS_OK(ret)) {
				return ret;
			}

			/* Point the return values at the NDR data. Remember to remove any ss padding. */
			*ppdata = prs_data_p(current_pdu) + RPC_HEADER_LEN + RPC_HDR_RESP_LEN;

			if (current_pdu_len < RPC_HEADER_LEN + RPC_HDR_RESP_LEN + ss_padding_len) {
				return NT_STATUS_BUFFER_TOO_SMALL;
			}

			*pdata_len = current_pdu_len - RPC_HEADER_LEN - RPC_HDR_RESP_LEN - ss_padding_len;

			/* Remember to remove the auth footer. */
			if (prhdr->auth_len) {
				/* We've already done integer wrap tests on auth_len in
					cli_pipe_validate_rpc_response(). */
				if (*pdata_len < RPC_HDR_AUTH_LEN + prhdr->auth_len) {
					return NT_STATUS_BUFFER_TOO_SMALL;
				}
				*pdata_len -= (RPC_HDR_AUTH_LEN + prhdr->auth_len);
			}

			DEBUG(10,("cli_pipe_validate_current_pdu: got pdu len %u, data_len %u, ss_len %u\n",
				current_pdu_len, *pdata_len, ss_padding_len ));

			/*
			 * If this is the first reply, and the allocation hint is reasonably, try and
			 * set up the return_data parse_struct to the correct size.
			 */

			if ((prs_data_size(return_data) == 0) && rhdr_resp.alloc_hint && (rhdr_resp.alloc_hint < 15*1024*1024)) {
				if (!prs_set_buffer_size(return_data, rhdr_resp.alloc_hint)) {
					DEBUG(0,("cli_pipe_validate_current_pdu: reply alloc hint %u "
						"too large to allocate\n",
						(unsigned int)rhdr_resp.alloc_hint ));
					return NT_STATUS_NO_MEMORY;
				}
			}

			break;
		}

		case RPC_BINDNACK:
			DEBUG(1, ("cli_pipe_validate_current_pdu: Bind NACK "
				  "received from %s!\n",
				  rpccli_pipe_txt(debug_ctx(), cli)));
			/* Use this for now... */
			return NT_STATUS_NETWORK_ACCESS_DENIED;

		case RPC_FAULT:
		{
			RPC_HDR_RESP rhdr_resp;
			RPC_HDR_FAULT fault_resp;

			if(!smb_io_rpc_hdr_resp("rpc_hdr_resp", &rhdr_resp, current_pdu, 0)) {
				DEBUG(5,("cli_pipe_validate_current_pdu: failed to unmarshal RPC_HDR_RESP.\n"));
				return NT_STATUS_BUFFER_TOO_SMALL;
			}

			if(!smb_io_rpc_hdr_fault("fault", &fault_resp, current_pdu, 0)) {
				DEBUG(5,("cli_pipe_validate_current_pdu: failed to unmarshal RPC_HDR_FAULT.\n"));
				return NT_STATUS_BUFFER_TOO_SMALL;
			}

			DEBUG(1, ("cli_pipe_validate_current_pdu: RPC fault "
				  "code %s received from %s!\n",
				dcerpc_errstr(NT_STATUS_V(fault_resp.status)),
				rpccli_pipe_txt(debug_ctx(), cli)));
			if (NT_STATUS_IS_OK(fault_resp.status)) {
				return NT_STATUS_UNSUCCESSFUL;
			} else {
				return fault_resp.status;
			}
		}

		default:
			DEBUG(0, ("cli_pipe_validate_current_pdu: unknown packet type %u received "
				"from %s!\n",
				(unsigned int)prhdr->pkt_type,
				rpccli_pipe_txt(debug_ctx(), cli)));
			return NT_STATUS_INVALID_INFO_CLASS;
	}

	if (prhdr->pkt_type != expected_pkt_type) {
		DEBUG(3, ("cli_pipe_validate_current_pdu: Connection to %s "
			  "got an unexpected RPC packet type - %u, not %u\n",
			rpccli_pipe_txt(debug_ctx(), cli),
			prhdr->pkt_type,
			expected_pkt_type));
		return NT_STATUS_INVALID_INFO_CLASS;
	}

	/* Do this just before return - we don't want to modify any rpc header
	   data before now as we may have needed to do cryptographic actions on
	   it before. */

	if ((prhdr->pkt_type == RPC_BINDACK) && !(prhdr->flags & RPC_FLG_LAST)) {
		DEBUG(5,("cli_pipe_validate_current_pdu: bug in server (AS/U?), "
			"setting fragment first/last ON.\n"));
		prhdr->flags |= RPC_FLG_FIRST|RPC_FLG_LAST;
	}

	return NT_STATUS_OK;
}

/****************************************************************************
 Ensure we eat the just processed pdu from the current_pdu prs_struct.
 Normally the frag_len and buffer size will match, but on the first trans
 reply there is a theoretical chance that buffer size > frag_len, so we must
 deal with that.
 ****************************************************************************/

static NTSTATUS cli_pipe_reset_current_pdu(struct rpc_pipe_client *cli, RPC_HDR *prhdr, prs_struct *current_pdu)
{
	uint32 current_pdu_len = prs_data_size(current_pdu);

	if (current_pdu_len < prhdr->frag_len) {
		return NT_STATUS_BUFFER_TOO_SMALL;
	}

	/* Common case. */
	if (current_pdu_len == (uint32)prhdr->frag_len) {
		prs_mem_free(current_pdu);
		prs_init_empty(current_pdu, prs_get_mem_context(current_pdu), UNMARSHALL);
		/* Make current_pdu dynamic with no memory. */
		prs_give_memory(current_pdu, 0, 0, True);
		return NT_STATUS_OK;
	}

	/*
	 * Oh no ! More data in buffer than we processed in current pdu.
	 * Cheat. Move the data down and shrink the buffer.
	 */

	memcpy(prs_data_p(current_pdu), prs_data_p(current_pdu) + prhdr->frag_len,
			current_pdu_len - prhdr->frag_len);

	/* Remember to set the read offset back to zero. */
	prs_set_offset(current_pdu, 0);

	/* Shrink the buffer. */
	if (!prs_set_buffer_size(current_pdu, current_pdu_len - prhdr->frag_len)) {
		return NT_STATUS_BUFFER_TOO_SMALL;
	}

	return NT_STATUS_OK;
}

/****************************************************************************
 Send data on an rpc pipe via trans. The prs_struct data must be the last
 pdu fragment of an NDR data stream.

 Receive response data from an rpc pipe, which may be large...

 Read the first fragment: unfortunately have to use SMBtrans for the first
 bit, then SMBreadX for subsequent bits.

 If first fragment received also wasn't the last fragment, continue
 getting fragments until we _do_ receive the last fragment.

 Request/Response PDU's look like the following...

 |<------------------PDU len----------------------------------------------->|
 |<-HDR_LEN-->|<--REQ LEN------>|.............|<-AUTH_HDRLEN->|<-AUTH_LEN-->|

 +------------+-----------------+-------------+---------------+-------------+
 | RPC HEADER | REQ/RESP HEADER | DATA ...... | AUTH_HDR      | AUTH DATA   |
 +------------+-----------------+-------------+---------------+-------------+

 Where the presence of the AUTH_HDR and AUTH DATA are dependent on the
 signing & sealing being negotiated.

 ****************************************************************************/

static NTSTATUS rpc_api_pipe(struct rpc_pipe_client *cli,
			prs_struct *data, /* Outgoing pdu fragment, already formatted for send. */
			prs_struct *rbuf, /* Incoming reply - return as an NDR stream. */
			uint8 expected_pkt_type)
{
	NTSTATUS ret = NT_STATUS_UNSUCCESSFUL;
	char *rparam = NULL;
	uint32 rparam_len = 0;
	char *pdata = prs_data_p(data);
	uint32 data_len = prs_offset(data);
	char *prdata = NULL;
	uint32 rdata_len = 0;
	uint32 max_data = cli->max_xmit_frag ? cli->max_xmit_frag : RPC_MAX_PDU_FRAG_LEN;
	uint32 current_rbuf_offset = 0;
	prs_struct current_pdu;

#ifdef DEVELOPER
	/* Ensure we're not sending too much. */
	SMB_ASSERT(data_len <= max_data);
#endif

	/* Set up the current pdu parse struct. */
	prs_init_empty(&current_pdu, prs_get_mem_context(rbuf), UNMARSHALL);

	DEBUG(5,("rpc_api_pipe: %s\n", rpccli_pipe_txt(debug_ctx(), cli)));

	switch (cli->transport_type) {
	case NCACN_NP: {
		uint16 setup[2];
		/* Create setup parameters - must be in native byte order. */
		setup[0] = TRANSACT_DCERPCCMD;
		setup[1] = cli->trans.np.fnum; /* Pipe file handle. */

		/*
		 * Send the last (or only) fragment of an RPC request. For
		 * small amounts of data (about 1024 bytes or so) the RPC
		 * request and response appears in a SMBtrans request and
		 * response.
		 */

		if (!cli_api_pipe(cli->trans.np.cli, "\\PIPE\\",
				  setup, 2, 0,     /* Setup, length, max */
				  NULL, 0, 0,      /* Params, length, max */
				  pdata, data_len, max_data, /* data, length,
							      * max */
				  &rparam, &rparam_len, /* return params,
							 * len */
				  &prdata, &rdata_len)) /* return data, len */
		{
			DEBUG(0, ("rpc_api_pipe: %s returned critical error. "
				  "Error was %s\n",
				  rpccli_pipe_txt(debug_ctx(), cli),
				  cli_errstr(cli->trans.np.cli)));
			ret = cli_get_nt_error(cli->trans.np.cli);
			SAFE_FREE(rparam);
			SAFE_FREE(prdata);
			goto err;
		}
		break;
	}
	case NCACN_IP_TCP:
	case NCACN_UNIX_STREAM:
	{
		ssize_t nwritten, nread;
		nwritten = write_data(cli->trans.sock.fd, pdata, data_len);
		if (nwritten == -1) {
			ret = map_nt_error_from_unix(errno);
			DEBUG(0, ("rpc_api_pipe: write_data returned %s\n",
				  strerror(errno)));
			goto err;
		}
		rparam = NULL;
		prdata = SMB_MALLOC_ARRAY(char, 1);
		if (prdata == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
		nread = sys_read(cli->trans.sock.fd, prdata, 1);
		if (nread == 0) {
			SAFE_FREE(prdata);
		}
		if (nread == -1) {
			ret = NT_STATUS_END_OF_FILE;
			goto err;
		}
		rdata_len = nread;
		break;
	}
	default:
		DEBUG(0, ("unknown transport type %d\n",
			  cli->transport_type));
		return NT_STATUS_INTERNAL_ERROR;
	}

	/* Throw away returned params - we know we won't use them. */

	SAFE_FREE(rparam);

	if (prdata == NULL) {
		DEBUG(3,("rpc_api_pipe: %s failed to return data.\n",
			 rpccli_pipe_txt(debug_ctx(), cli)));
		/* Yes - some calls can truely return no data... */
		prs_mem_free(&current_pdu);
		return NT_STATUS_OK;
	}

	/*
	 * Give this memory as dynamic to the current pdu.
	 */

	prs_give_memory(&current_pdu, prdata, rdata_len, True);

	/* Ensure we can mess with the return prs_struct. */
	SMB_ASSERT(UNMARSHALLING(rbuf));
	SMB_ASSERT(prs_data_size(rbuf) == 0);

	/* Make rbuf dynamic with no memory. */
	prs_give_memory(rbuf, 0, 0, True);

	while(1) {
		RPC_HDR rhdr;
		char *ret_data = NULL;
		uint32 ret_data_len = 0;

		/* Ensure we have enough data for a pdu. */
		ret = cli_pipe_get_current_pdu(cli, &rhdr, &current_pdu);
		if (!NT_STATUS_IS_OK(ret)) {
			goto err;
		}

		/* We pass in rbuf here so if the alloc hint is set correctly 
		   we can set the output size and avoid reallocs. */

		ret = cli_pipe_validate_current_pdu(cli, &rhdr, &current_pdu, expected_pkt_type,
				&ret_data, &ret_data_len, rbuf);

		DEBUG(10,("rpc_api_pipe: got PDU len of %u at offset %u\n",
			prs_data_size(&current_pdu), current_rbuf_offset ));

		if (!NT_STATUS_IS_OK(ret)) {
			goto err;
		}

		if ((rhdr.flags & RPC_FLG_FIRST)) {
			if (rhdr.pack_type[0] == 0) {
				/* Set the data type correctly for big-endian data on the first packet. */
				DEBUG(10,("rpc_api_pipe: On %s "
					"PDU data format is big-endian.\n",
					rpccli_pipe_txt(debug_ctx(), cli)));

				prs_set_endian_data(rbuf, RPC_BIG_ENDIAN);
			} else {
				/* Check endianness on subsequent packets. */
				if (current_pdu.bigendian_data != rbuf->bigendian_data) {
					DEBUG(0,("rpc_api_pipe: Error : Endianness changed from %s to %s\n",
						rbuf->bigendian_data ? "big" : "little",
						current_pdu.bigendian_data ? "big" : "little" ));
					ret = NT_STATUS_INVALID_PARAMETER;
					goto err;
				}
			}
		}

		/* Now copy the data portion out of the pdu into rbuf. */
		if (!prs_force_grow(rbuf, ret_data_len)) {
                        ret = NT_STATUS_NO_MEMORY;
                        goto err;
                }
		memcpy(prs_data_p(rbuf)+current_rbuf_offset, ret_data, (size_t)ret_data_len);
		current_rbuf_offset += ret_data_len;

		/* See if we've finished with all the data in current_pdu yet ? */
		ret = cli_pipe_reset_current_pdu(cli, &rhdr, &current_pdu);
		if (!NT_STATUS_IS_OK(ret)) {
			goto err;
		}

		if (rhdr.flags & RPC_FLG_LAST) {
			break; /* We're done. */
		}
	}

	DEBUG(10,("rpc_api_pipe: %s returned %u bytes.\n",
		rpccli_pipe_txt(debug_ctx(), cli),
		(unsigned int)prs_data_size(rbuf) ));

	prs_mem_free(&current_pdu);
	return NT_STATUS_OK;

  err:

	prs_mem_free(&current_pdu);
	prs_mem_free(rbuf);
	return ret;
}

/*******************************************************************
 Creates krb5 auth bind.
 ********************************************************************/

static NTSTATUS create_krb5_auth_bind_req( struct rpc_pipe_client *cli,
						enum pipe_auth_level auth_level,
						RPC_HDR_AUTH *pauth_out,
						prs_struct *auth_data)
{
#ifdef HAVE_KRB5
	int ret;
	struct kerberos_auth_struct *a = cli->auth->a_u.kerberos_auth;
	DATA_BLOB tkt = data_blob_null;
	DATA_BLOB tkt_wrapped = data_blob_null;

	/* We may change the pad length before marshalling. */
	init_rpc_hdr_auth(pauth_out, RPC_KRB5_AUTH_TYPE, (int)auth_level, 0, 1);

	DEBUG(5, ("create_krb5_auth_bind_req: creating a service ticket for principal %s\n",
		a->service_principal ));

	/* Create the ticket for the service principal and return it in a gss-api wrapped blob. */

	ret = cli_krb5_get_ticket(a->service_principal, 0, &tkt,
			&a->session_key, (uint32)AP_OPTS_MUTUAL_REQUIRED, NULL, NULL);

	if (ret) {
		DEBUG(1,("create_krb5_auth_bind_req: cli_krb5_get_ticket for principal %s "
			"failed with %s\n",
			a->service_principal,
			error_message(ret) ));

		data_blob_free(&tkt);
		prs_mem_free(auth_data);
		return NT_STATUS_INVALID_PARAMETER;
	}

	/* wrap that up in a nice GSS-API wrapping */
	tkt_wrapped = spnego_gen_krb5_wrap(tkt, TOK_ID_KRB_AP_REQ);

	data_blob_free(&tkt);

	/* Auth len in the rpc header doesn't include auth_header. */
	if (!prs_copy_data_in(auth_data, (char *)tkt_wrapped.data, tkt_wrapped.length)) {
		data_blob_free(&tkt_wrapped);
		prs_mem_free(auth_data);
		return NT_STATUS_NO_MEMORY;
	}

	DEBUG(5, ("create_krb5_auth_bind_req: Created krb5 GSS blob :\n"));
	dump_data(5, tkt_wrapped.data, tkt_wrapped.length);

	data_blob_free(&tkt_wrapped);
	return NT_STATUS_OK;
#else
	return NT_STATUS_INVALID_PARAMETER;
#endif
}

/*******************************************************************
 Creates SPNEGO NTLMSSP auth bind.
 ********************************************************************/

static NTSTATUS create_spnego_ntlmssp_auth_rpc_bind_req( struct rpc_pipe_client *cli,
						enum pipe_auth_level auth_level,
						RPC_HDR_AUTH *pauth_out,
						prs_struct *auth_data)
{
	NTSTATUS nt_status;
	DATA_BLOB null_blob = data_blob_null;
	DATA_BLOB request = data_blob_null;
	DATA_BLOB spnego_msg = data_blob_null;

	/* We may change the pad length before marshalling. */
	init_rpc_hdr_auth(pauth_out, RPC_SPNEGO_AUTH_TYPE, (int)auth_level, 0, 1);

	DEBUG(5, ("create_spnego_ntlmssp_auth_rpc_bind_req: Processing NTLMSSP Negotiate\n"));
	nt_status = ntlmssp_update(cli->auth->a_u.ntlmssp_state,
					null_blob,
					&request);

	if (!NT_STATUS_EQUAL(nt_status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		data_blob_free(&request);
		prs_mem_free(auth_data);
		return nt_status;
	}

	/* Wrap this in SPNEGO. */
	spnego_msg = gen_negTokenInit(OID_NTLMSSP, request);

	data_blob_free(&request);

	/* Auth len in the rpc header doesn't include auth_header. */
	if (!prs_copy_data_in(auth_data, (char *)spnego_msg.data, spnego_msg.length)) {
		data_blob_free(&spnego_msg);
		prs_mem_free(auth_data);
		return NT_STATUS_NO_MEMORY;
	}

	DEBUG(5, ("create_spnego_ntlmssp_auth_rpc_bind_req: NTLMSSP Negotiate:\n"));
	dump_data(5, spnego_msg.data, spnego_msg.length);

	data_blob_free(&spnego_msg);
	return NT_STATUS_OK;
}

/*******************************************************************
 Creates NTLMSSP auth bind.
 ********************************************************************/

static NTSTATUS create_ntlmssp_auth_rpc_bind_req( struct rpc_pipe_client *cli,
						enum pipe_auth_level auth_level,
						RPC_HDR_AUTH *pauth_out,
						prs_struct *auth_data)
{
	NTSTATUS nt_status;
	DATA_BLOB null_blob = data_blob_null;
	DATA_BLOB request = data_blob_null;

	/* We may change the pad length before marshalling. */
	init_rpc_hdr_auth(pauth_out, RPC_NTLMSSP_AUTH_TYPE, (int)auth_level, 0, 1);

	DEBUG(5, ("create_ntlmssp_auth_rpc_bind_req: Processing NTLMSSP Negotiate\n"));
	nt_status = ntlmssp_update(cli->auth->a_u.ntlmssp_state,
					null_blob,
					&request);

	if (!NT_STATUS_EQUAL(nt_status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		data_blob_free(&request);
		prs_mem_free(auth_data);
		return nt_status;
	}

	/* Auth len in the rpc header doesn't include auth_header. */
	if (!prs_copy_data_in(auth_data, (char *)request.data, request.length)) {
		data_blob_free(&request);
		prs_mem_free(auth_data);
		return NT_STATUS_NO_MEMORY;
	}

	DEBUG(5, ("create_ntlmssp_auth_rpc_bind_req: NTLMSSP Negotiate:\n"));
	dump_data(5, request.data, request.length);

	data_blob_free(&request);
	return NT_STATUS_OK;
}

/*******************************************************************
 Creates schannel auth bind.
 ********************************************************************/

static NTSTATUS create_schannel_auth_rpc_bind_req( struct rpc_pipe_client *cli,
						enum pipe_auth_level auth_level,
						RPC_HDR_AUTH *pauth_out,
						prs_struct *auth_data)
{
	RPC_AUTH_SCHANNEL_NEG schannel_neg;

	/* We may change the pad length before marshalling. */
	init_rpc_hdr_auth(pauth_out, RPC_SCHANNEL_AUTH_TYPE, (int)auth_level, 0, 1);

	/* Use lp_workgroup() if domain not specified */

	if (!cli->auth->domain || !cli->auth->domain[0]) {
		cli->auth->domain = talloc_strdup(cli, lp_workgroup());
		if (cli->auth->domain == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
	}

	init_rpc_auth_schannel_neg(&schannel_neg, cli->auth->domain,
				   global_myname());

	/*
	 * Now marshall the data into the auth parse_struct.
	 */

	if(!smb_io_rpc_auth_schannel_neg("schannel_neg",
				       &schannel_neg, auth_data, 0)) {
		DEBUG(0,("Failed to marshall RPC_AUTH_SCHANNEL_NEG.\n"));
		prs_mem_free(auth_data);
		return NT_STATUS_NO_MEMORY;
	}

	return NT_STATUS_OK;
}

/*******************************************************************
 Creates the internals of a DCE/RPC bind request or alter context PDU.
 ********************************************************************/

static NTSTATUS create_bind_or_alt_ctx_internal(enum RPC_PKT_TYPE pkt_type,
						prs_struct *rpc_out, 
						uint32 rpc_call_id,
						const RPC_IFACE *abstract,
						const RPC_IFACE *transfer,
						RPC_HDR_AUTH *phdr_auth,
						prs_struct *pauth_info)
{
	RPC_HDR hdr;
	RPC_HDR_RB hdr_rb;
	RPC_CONTEXT rpc_ctx;
	uint16 auth_len = prs_offset(pauth_info);
	uint8 ss_padding_len = 0;
	uint16 frag_len = 0;

	/* create the RPC context. */
	init_rpc_context(&rpc_ctx, 0 /* context id */, abstract, transfer);

	/* create the bind request RPC_HDR_RB */
	init_rpc_hdr_rb(&hdr_rb, RPC_MAX_PDU_FRAG_LEN, RPC_MAX_PDU_FRAG_LEN, 0x0, &rpc_ctx);

	/* Start building the frag length. */
	frag_len = RPC_HEADER_LEN + RPC_HDR_RB_LEN(&hdr_rb);

	/* Do we need to pad ? */
	if (auth_len) {
		uint16 data_len = RPC_HEADER_LEN + RPC_HDR_RB_LEN(&hdr_rb);
		if (data_len % 8) {
			ss_padding_len = 8 - (data_len % 8);
			phdr_auth->auth_pad_len = ss_padding_len;
		}
		frag_len += RPC_HDR_AUTH_LEN + auth_len + ss_padding_len;
	}

	/* Create the request RPC_HDR */
	init_rpc_hdr(&hdr, pkt_type, RPC_FLG_FIRST|RPC_FLG_LAST, rpc_call_id, frag_len, auth_len);

	/* Marshall the RPC header */
	if(!smb_io_rpc_hdr("hdr"   , &hdr, rpc_out, 0)) {
		DEBUG(0,("create_bind_or_alt_ctx_internal: failed to marshall RPC_HDR.\n"));
		return NT_STATUS_NO_MEMORY;
	}

	/* Marshall the bind request data */
	if(!smb_io_rpc_hdr_rb("", &hdr_rb, rpc_out, 0)) {
		DEBUG(0,("create_bind_or_alt_ctx_internal: failed to marshall RPC_HDR_RB.\n"));
		return NT_STATUS_NO_MEMORY;
	}

	/*
	 * Grow the outgoing buffer to store any auth info.
	 */

	if(auth_len != 0) {
		if (ss_padding_len) {
			char pad[8];
			memset(pad, '\0', 8);
			if (!prs_copy_data_in(rpc_out, pad, ss_padding_len)) {
				DEBUG(0,("create_bind_or_alt_ctx_internal: failed to marshall padding.\n"));
				return NT_STATUS_NO_MEMORY;
			}
		}

		if(!smb_io_rpc_hdr_auth("hdr_auth", phdr_auth, rpc_out, 0)) {
			DEBUG(0,("create_bind_or_alt_ctx_internal: failed to marshall RPC_HDR_AUTH.\n"));
			return NT_STATUS_NO_MEMORY;
		}


		if(!prs_append_prs_data( rpc_out, pauth_info)) {
			DEBUG(0,("create_bind_or_alt_ctx_internal: failed to grow parse struct to add auth.\n"));
			return NT_STATUS_NO_MEMORY;
		}
	}

	return NT_STATUS_OK;
}

/*******************************************************************
 Creates a DCE/RPC bind request.
 ********************************************************************/

static NTSTATUS create_rpc_bind_req(struct rpc_pipe_client *cli,
				prs_struct *rpc_out, 
				uint32 rpc_call_id,
				const RPC_IFACE *abstract,
				const RPC_IFACE *transfer,
				enum pipe_auth_type auth_type,
				enum pipe_auth_level auth_level)
{
	RPC_HDR_AUTH hdr_auth;
	prs_struct auth_info;
	NTSTATUS ret = NT_STATUS_OK;

	ZERO_STRUCT(hdr_auth);
	if (!prs_init(&auth_info, RPC_HDR_AUTH_LEN, prs_get_mem_context(rpc_out), MARSHALL))
		return NT_STATUS_NO_MEMORY;

	switch (auth_type) {
		case PIPE_AUTH_TYPE_SCHANNEL:
			ret = create_schannel_auth_rpc_bind_req(cli, auth_level, &hdr_auth, &auth_info);
			if (!NT_STATUS_IS_OK(ret)) {
				prs_mem_free(&auth_info);
				return ret;
			}
			break;

		case PIPE_AUTH_TYPE_NTLMSSP:
			ret = create_ntlmssp_auth_rpc_bind_req(cli, auth_level, &hdr_auth, &auth_info);
			if (!NT_STATUS_IS_OK(ret)) {
				prs_mem_free(&auth_info);
				return ret;
			}
			break;

		case PIPE_AUTH_TYPE_SPNEGO_NTLMSSP:
			ret = create_spnego_ntlmssp_auth_rpc_bind_req(cli, auth_level, &hdr_auth, &auth_info);
			if (!NT_STATUS_IS_OK(ret)) {
				prs_mem_free(&auth_info);
				return ret;
			}
			break;

		case PIPE_AUTH_TYPE_KRB5:
			ret = create_krb5_auth_bind_req(cli, auth_level, &hdr_auth, &auth_info);
			if (!NT_STATUS_IS_OK(ret)) {
				prs_mem_free(&auth_info);
				return ret;
			}
			break;

		case PIPE_AUTH_TYPE_NONE:
			break;

		default:
			/* "Can't" happen. */
			return NT_STATUS_INVALID_INFO_CLASS;
	}

	ret = create_bind_or_alt_ctx_internal(RPC_BIND,
						rpc_out, 
						rpc_call_id,
						abstract,
						transfer,
						&hdr_auth,
						&auth_info);

	prs_mem_free(&auth_info);
	return ret;
}

/*******************************************************************
 Create and add the NTLMSSP sign/seal auth header and data.
 ********************************************************************/

static NTSTATUS add_ntlmssp_auth_footer(struct rpc_pipe_client *cli,
					RPC_HDR *phdr,
					uint32 ss_padding_len,
					prs_struct *outgoing_pdu)
{
	RPC_HDR_AUTH auth_info;
	NTSTATUS status;
	DATA_BLOB auth_blob = data_blob_null;
	uint16 data_and_pad_len = prs_offset(outgoing_pdu) - RPC_HEADER_LEN - RPC_HDR_RESP_LEN;

	if (!cli->auth->a_u.ntlmssp_state) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	/* Init and marshall the auth header. */
	init_rpc_hdr_auth(&auth_info,
			map_pipe_auth_type_to_rpc_auth_type(
				cli->auth->auth_type),
			cli->auth->auth_level,
			ss_padding_len,
			1 /* context id. */);

	if(!smb_io_rpc_hdr_auth("hdr_auth", &auth_info, outgoing_pdu, 0)) {
		DEBUG(0,("add_ntlmssp_auth_footer: failed to marshall RPC_HDR_AUTH.\n"));
		data_blob_free(&auth_blob);
		return NT_STATUS_NO_MEMORY;
	}

	switch (cli->auth->auth_level) {
		case PIPE_AUTH_LEVEL_PRIVACY:
			/* Data portion is encrypted. */
			status = ntlmssp_seal_packet(cli->auth->a_u.ntlmssp_state,
					(unsigned char *)prs_data_p(outgoing_pdu) + RPC_HEADER_LEN + RPC_HDR_RESP_LEN,
					data_and_pad_len,
					(unsigned char *)prs_data_p(outgoing_pdu),
					(size_t)prs_offset(outgoing_pdu),
					&auth_blob);
			if (!NT_STATUS_IS_OK(status)) {
				data_blob_free(&auth_blob);
				return status;
			}
			break;

		case PIPE_AUTH_LEVEL_INTEGRITY:
			/* Data is signed. */
			status = ntlmssp_sign_packet(cli->auth->a_u.ntlmssp_state,
					(unsigned char *)prs_data_p(outgoing_pdu) + RPC_HEADER_LEN + RPC_HDR_RESP_LEN,
					data_and_pad_len,
					(unsigned char *)prs_data_p(outgoing_pdu),
					(size_t)prs_offset(outgoing_pdu),
					&auth_blob);
			if (!NT_STATUS_IS_OK(status)) {
				data_blob_free(&auth_blob);
				return status;
			}
			break;

		default:
			/* Can't happen. */
			smb_panic("bad auth level");
			/* Notreached. */
			return NT_STATUS_INVALID_PARAMETER;
	}

	/* Finally marshall the blob. */

	if (!prs_copy_data_in(outgoing_pdu, (const char *)auth_blob.data, NTLMSSP_SIG_SIZE)) {
		DEBUG(0,("add_ntlmssp_auth_footer: failed to add %u bytes auth blob.\n",
			(unsigned int)NTLMSSP_SIG_SIZE));
		data_blob_free(&auth_blob);
		return NT_STATUS_NO_MEMORY;
	}

	data_blob_free(&auth_blob);
	return NT_STATUS_OK;
}

/*******************************************************************
 Create and add the schannel sign/seal auth header and data.
 ********************************************************************/

static NTSTATUS add_schannel_auth_footer(struct rpc_pipe_client *cli,
					RPC_HDR *phdr,
					uint32 ss_padding_len,
					prs_struct *outgoing_pdu)
{
	RPC_HDR_AUTH auth_info;
	RPC_AUTH_SCHANNEL_CHK verf;
	struct schannel_auth_struct *sas = cli->auth->a_u.schannel_auth;
	char *data_p = prs_data_p(outgoing_pdu) + RPC_HEADER_LEN + RPC_HDR_RESP_LEN;
	size_t data_and_pad_len = prs_offset(outgoing_pdu) - RPC_HEADER_LEN - RPC_HDR_RESP_LEN;

	if (!sas) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	/* Init and marshall the auth header. */
	init_rpc_hdr_auth(&auth_info,
			map_pipe_auth_type_to_rpc_auth_type(cli->auth->auth_type),
			cli->auth->auth_level,
			ss_padding_len,
			1 /* context id. */);

	if(!smb_io_rpc_hdr_auth("hdr_auth", &auth_info, outgoing_pdu, 0)) {
		DEBUG(0,("add_schannel_auth_footer: failed to marshall RPC_HDR_AUTH.\n"));
		return NT_STATUS_NO_MEMORY;
	}

	switch (cli->auth->auth_level) {
		case PIPE_AUTH_LEVEL_PRIVACY:
		case PIPE_AUTH_LEVEL_INTEGRITY:
			DEBUG(10,("add_schannel_auth_footer: SCHANNEL seq_num=%d\n",
				sas->seq_num));

			schannel_encode(sas,
					cli->auth->auth_level,
					SENDER_IS_INITIATOR,
					&verf,
					data_p,
					data_and_pad_len);

			sas->seq_num++;
			break;

		default:
			/* Can't happen. */
			smb_panic("bad auth level");
			/* Notreached. */
			return NT_STATUS_INVALID_PARAMETER;
	}

	/* Finally marshall the blob. */
	smb_io_rpc_auth_schannel_chk("",
			RPC_AUTH_SCHANNEL_SIGN_OR_SEAL_CHK_LEN,
			&verf,
			outgoing_pdu,
			0);

	return NT_STATUS_OK;
}

/*******************************************************************
 Calculate how much data we're going to send in this packet, also
 work out any sign/seal padding length.
 ********************************************************************/

static uint32 calculate_data_len_tosend(struct rpc_pipe_client *cli,
					uint32 data_left,
					uint16 *p_frag_len,
					uint16 *p_auth_len,
					uint32 *p_ss_padding)
{
	uint32 data_space, data_len;

	switch (cli->auth->auth_level) {
		case PIPE_AUTH_LEVEL_NONE:
		case PIPE_AUTH_LEVEL_CONNECT:
			data_space = cli->max_xmit_frag - RPC_HEADER_LEN - RPC_HDR_REQ_LEN;
			data_len = MIN(data_space, data_left);
			*p_ss_padding = 0;
			*p_auth_len = 0;
			*p_frag_len = RPC_HEADER_LEN + RPC_HDR_REQ_LEN + data_len;
			return data_len;

		case PIPE_AUTH_LEVEL_INTEGRITY:
		case PIPE_AUTH_LEVEL_PRIVACY:
			/* Treat the same for all authenticated rpc requests. */
			switch(cli->auth->auth_type) {
				case PIPE_AUTH_TYPE_SPNEGO_NTLMSSP:
				case PIPE_AUTH_TYPE_NTLMSSP:
					*p_auth_len = NTLMSSP_SIG_SIZE;
					break;
				case PIPE_AUTH_TYPE_SCHANNEL:
					*p_auth_len = RPC_AUTH_SCHANNEL_SIGN_OR_SEAL_CHK_LEN;
					break;
				default:
					smb_panic("bad auth type");
					break;
			}

			data_space = cli->max_xmit_frag - RPC_HEADER_LEN - RPC_HDR_REQ_LEN -
						RPC_HDR_AUTH_LEN - *p_auth_len;

			data_len = MIN(data_space, data_left);
			if (data_len % 8) {
				*p_ss_padding = 8 - (data_len % 8);
			}
			*p_frag_len = RPC_HEADER_LEN + RPC_HDR_REQ_LEN + 		/* Normal headers. */
					data_len + *p_ss_padding + 		/* data plus padding. */
					RPC_HDR_AUTH_LEN + *p_auth_len;		/* Auth header and auth data. */
			return data_len;

		default:
			smb_panic("bad auth level");
			/* Notreached. */
			return 0;
	}
}

/*******************************************************************
 External interface.
 Does an rpc request on a pipe. Incoming data is NDR encoded in in_data.
 Reply is NDR encoded in out_data. Splits the data stream into RPC PDU's
 and deals with signing/sealing details.
 ********************************************************************/

NTSTATUS rpc_api_pipe_req(struct rpc_pipe_client *cli,
			uint8 op_num,
			prs_struct *in_data,
			prs_struct *out_data)
{
	NTSTATUS ret;
	uint32 data_left = prs_offset(in_data);
	uint32 alloc_hint = prs_offset(in_data);
	uint32 data_sent_thistime = 0;
	uint32 current_data_offset = 0;
	uint32 call_id = get_rpc_call_id();
	char pad[8];
	prs_struct outgoing_pdu;

	memset(pad, '\0', 8);

	if (cli->max_xmit_frag < RPC_HEADER_LEN + RPC_HDR_REQ_LEN + RPC_MAX_SIGN_SIZE) {
		/* Server is screwed up ! */
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (!prs_init(&outgoing_pdu, cli->max_xmit_frag, prs_get_mem_context(in_data), MARSHALL))
		return NT_STATUS_NO_MEMORY;

	while (1) {
		RPC_HDR hdr;
		RPC_HDR_REQ hdr_req;
		uint16 auth_len = 0;
		uint16 frag_len = 0;
		uint8 flags = 0;
		uint32 ss_padding = 0;

		data_sent_thistime = calculate_data_len_tosend(cli, data_left,
						&frag_len, &auth_len, &ss_padding);

		if (current_data_offset == 0) {
			flags = RPC_FLG_FIRST;
		}

		if (data_sent_thistime == data_left) {
			flags |= RPC_FLG_LAST;
		}

		/* Create and marshall the header and request header. */
		init_rpc_hdr(&hdr, RPC_REQUEST, flags, call_id, frag_len, auth_len);

		if(!smb_io_rpc_hdr("hdr    ", &hdr, &outgoing_pdu, 0)) {
			prs_mem_free(&outgoing_pdu);
			return NT_STATUS_NO_MEMORY;
		}

		/* Create the rpc request RPC_HDR_REQ */
		init_rpc_hdr_req(&hdr_req, alloc_hint, op_num);

		if(!smb_io_rpc_hdr_req("hdr_req", &hdr_req, &outgoing_pdu, 0)) {
			prs_mem_free(&outgoing_pdu);
			return NT_STATUS_NO_MEMORY;
		}

		/* Copy in the data, plus any ss padding. */
		if (!prs_append_some_prs_data(&outgoing_pdu, in_data, current_data_offset, data_sent_thistime)) {
			prs_mem_free(&outgoing_pdu);
			return NT_STATUS_NO_MEMORY;
		}

		/* Copy the sign/seal padding data. */
		if (ss_padding) {
			if (!prs_copy_data_in(&outgoing_pdu, pad, ss_padding)) {
				prs_mem_free(&outgoing_pdu);
				return NT_STATUS_NO_MEMORY;
			}
		}

		/* Generate any auth sign/seal and add the auth footer. */
		if (auth_len) {
			switch (cli->auth->auth_type) {
				case PIPE_AUTH_TYPE_NONE:
					break;
				case PIPE_AUTH_TYPE_NTLMSSP:
				case PIPE_AUTH_TYPE_SPNEGO_NTLMSSP:
					ret = add_ntlmssp_auth_footer(cli, &hdr, ss_padding, &outgoing_pdu);
					if (!NT_STATUS_IS_OK(ret)) {
						prs_mem_free(&outgoing_pdu);
						return ret;
					}
					break;
				case PIPE_AUTH_TYPE_SCHANNEL:
					ret = add_schannel_auth_footer(cli, &hdr, ss_padding, &outgoing_pdu);
					if (!NT_STATUS_IS_OK(ret)) {
						prs_mem_free(&outgoing_pdu);
						return ret;
					}
					break;
				default:
					smb_panic("bad auth type");
					break; /* notreached */
			}
		}

		/* Actually send the packet. */
		if (flags & RPC_FLG_LAST) {
			/* Last packet - send the data, get the reply and return. */
			ret = rpc_api_pipe(cli, &outgoing_pdu, out_data, RPC_RESPONSE);
			prs_mem_free(&outgoing_pdu);

			if ((DEBUGLEVEL >= 50)
			    && (cli->transport_type == NCACN_NP)) {
				char *dump_name = NULL;
				/* Also capture received data */
				if (asprintf(&dump_name, "%s/reply_%s_%d",
					     get_dyn_LOGFILEBASE(),
					     cli->trans.np.pipe_name, op_num) > 0) {
					prs_dump(dump_name, op_num, out_data);
					SAFE_FREE(dump_name);
				}
			}

			return ret;
		} else {
			/* More packets to come - write and continue. */
			ssize_t num_written;

			switch (cli->transport_type) {
			case NCACN_NP:
				num_written = cli_write(cli->trans.np.cli,
							cli->trans.np.fnum,
							8, /* 8 means message mode. */
							prs_data_p(&outgoing_pdu),
							(off_t)0,
							(size_t)hdr.frag_len);

				if (num_written != hdr.frag_len) {
					prs_mem_free(&outgoing_pdu);
					return cli_get_nt_error(
						cli->trans.np.cli);
				}
				break;
			case NCACN_IP_TCP:
			case NCACN_UNIX_STREAM:
				num_written = write_data(
					cli->trans.sock.fd,
					prs_data_p(&outgoing_pdu),
					(size_t)hdr.frag_len);
				if (num_written != hdr.frag_len) {
					NTSTATUS status;
					status = map_nt_error_from_unix(errno);
					prs_mem_free(&outgoing_pdu);
					return status;
				}
				break;
			default:
				DEBUG(0, ("unknown transport type %d\n",
					  cli->transport_type));
				return NT_STATUS_INTERNAL_ERROR;
			}
		}

		current_data_offset += data_sent_thistime;
		data_left -= data_sent_thistime;

		/* Reset the marshalling position back to zero. */
		if (!prs_set_offset(&outgoing_pdu, 0)) {
			prs_mem_free(&outgoing_pdu);
			return NT_STATUS_NO_MEMORY;
		}
	}
}
#if 0
/****************************************************************************
 Set the handle state.
****************************************************************************/

static bool rpc_pipe_set_hnd_state(struct rpc_pipe_client *cli,
				   const char *pipe_name, uint16 device_state)
{
	bool state_set = False;
	char param[2];
	uint16 setup[2]; /* only need 2 uint16 setup parameters */
	char *rparam = NULL;
	char *rdata = NULL;
	uint32 rparam_len, rdata_len;

	if (pipe_name == NULL)
		return False;

	DEBUG(5,("Set Handle state Pipe[%x]: %s - device state:%x\n",
		 cli->fnum, pipe_name, device_state));

	/* create parameters: device state */
	SSVAL(param, 0, device_state);

	/* create setup parameters. */
	setup[0] = 0x0001; 
	setup[1] = cli->fnum; /* pipe file handle.  got this from an SMBOpenX. */

	/* send the data on \PIPE\ */
	if (cli_api_pipe(cli->cli, "\\PIPE\\",
	            setup, 2, 0,                /* setup, length, max */
	            param, 2, 0,                /* param, length, max */
	            NULL, 0, 1024,              /* data, length, max */
	            &rparam, &rparam_len,        /* return param, length */
	            &rdata, &rdata_len))         /* return data, length */
	{
		DEBUG(5, ("Set Handle state: return OK\n"));
		state_set = True;
	}

	SAFE_FREE(rparam);
	SAFE_FREE(rdata);

	return state_set;
}
#endif

/****************************************************************************
 Check the rpc bind acknowledge response.
****************************************************************************/

static bool check_bind_response(RPC_HDR_BA *hdr_ba, const RPC_IFACE *transfer)
{
	if ( hdr_ba->addr.len == 0) {
		DEBUG(4,("Ignoring length check -- ASU bug (server didn't fill in the pipe name correctly)"));
	}

	/* check the transfer syntax */
	if ((hdr_ba->transfer.if_version != transfer->if_version) ||
	     (memcmp(&hdr_ba->transfer.uuid, &transfer->uuid, sizeof(transfer->uuid)) !=0)) {
		DEBUG(2,("bind_rpc_pipe: transfer syntax differs\n"));
		return False;
	}

	if (hdr_ba->res.num_results != 0x1 || hdr_ba->res.result != 0) {
		DEBUG(2,("bind_rpc_pipe: bind denied results: %d reason: %x\n",
		          hdr_ba->res.num_results, hdr_ba->res.reason));
	}

	DEBUG(5,("check_bind_response: accepted!\n"));
	return True;
}

/*******************************************************************
 Creates a DCE/RPC bind authentication response.
 This is the packet that is sent back to the server once we
 have received a BIND-ACK, to finish the third leg of
 the authentication handshake.
 ********************************************************************/

static NTSTATUS create_rpc_bind_auth3(struct rpc_pipe_client *cli,
				uint32 rpc_call_id,
				enum pipe_auth_type auth_type,
				enum pipe_auth_level auth_level,
				DATA_BLOB *pauth_blob,
				prs_struct *rpc_out)
{
	RPC_HDR hdr;
	RPC_HDR_AUTH hdr_auth;
	uint32 pad = 0;

	/* Create the request RPC_HDR */
	init_rpc_hdr(&hdr, RPC_AUTH3, RPC_FLG_FIRST|RPC_FLG_LAST, rpc_call_id,
		     RPC_HEADER_LEN + 4 /* pad */ + RPC_HDR_AUTH_LEN + pauth_blob->length,
		     pauth_blob->length );

	/* Marshall it. */
	if(!smb_io_rpc_hdr("hdr", &hdr, rpc_out, 0)) {
		DEBUG(0,("create_rpc_bind_auth3: failed to marshall RPC_HDR.\n"));
		return NT_STATUS_NO_MEMORY;
	}

	/*
		I'm puzzled about this - seems to violate the DCE RPC auth rules,
		about padding - shouldn't this pad to length 8 ? JRA.
	*/

	/* 4 bytes padding. */
	if (!prs_uint32("pad", rpc_out, 0, &pad)) {
		DEBUG(0,("create_rpc_bind_auth3: failed to marshall 4 byte pad.\n"));
		return NT_STATUS_NO_MEMORY;
	}

	/* Create the request RPC_HDR_AUTHA */
	init_rpc_hdr_auth(&hdr_auth,
			map_pipe_auth_type_to_rpc_auth_type(auth_type),
			auth_level, 0, 1);

	if(!smb_io_rpc_hdr_auth("hdr_auth", &hdr_auth, rpc_out, 0)) {
		DEBUG(0,("create_rpc_bind_auth3: failed to marshall RPC_HDR_AUTHA.\n"));
		return NT_STATUS_NO_MEMORY;
	}

	/*
	 * Append the auth data to the outgoing buffer.
	 */

	if(!prs_copy_data_in(rpc_out, (char *)pauth_blob->data, pauth_blob->length)) {
		DEBUG(0,("create_rpc_bind_auth3: failed to marshall auth blob.\n"));
		return NT_STATUS_NO_MEMORY;
	}

	return NT_STATUS_OK;
}

/****************************************************************************
 Create and send the third packet in an RPC auth.
****************************************************************************/

static NTSTATUS rpc_finish_auth3_bind(struct rpc_pipe_client *cli,
				RPC_HDR *phdr,
				prs_struct *rbuf,
				uint32 rpc_call_id,
				enum pipe_auth_type auth_type,
				enum pipe_auth_level auth_level)
{
	DATA_BLOB server_response = data_blob_null;
	DATA_BLOB client_reply = data_blob_null;
	RPC_HDR_AUTH hdr_auth;
	NTSTATUS nt_status;
	prs_struct rpc_out;
	ssize_t ret;

	if (!phdr->auth_len || (phdr->frag_len < phdr->auth_len + RPC_HDR_AUTH_LEN)) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	/* Process the returned NTLMSSP blob first. */
	if (!prs_set_offset(rbuf, phdr->frag_len - phdr->auth_len - RPC_HDR_AUTH_LEN)) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if(!smb_io_rpc_hdr_auth("hdr_auth", &hdr_auth, rbuf, 0)) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	/* TODO - check auth_type/auth_level match. */

	server_response = data_blob(NULL, phdr->auth_len);
	prs_copy_data_out((char *)server_response.data, rbuf, phdr->auth_len);

	nt_status = ntlmssp_update(cli->auth->a_u.ntlmssp_state,
				   server_response,
				   &client_reply);

	if (!NT_STATUS_IS_OK(nt_status)) {
		DEBUG(0,("rpc_finish_auth3_bind: NTLMSSP update using server blob failed.\n"));
		data_blob_free(&server_response);
		return nt_status;
	}

	prs_init_empty(&rpc_out, prs_get_mem_context(rbuf), MARSHALL);

	nt_status = create_rpc_bind_auth3(cli, rpc_call_id,
				auth_type, auth_level,
				&client_reply, &rpc_out);

	if (!NT_STATUS_IS_OK(nt_status)) {
		prs_mem_free(&rpc_out);
		data_blob_free(&client_reply);
		data_blob_free(&server_response);
		return nt_status;
	}

	switch (cli->transport_type) {
	case NCACN_NP:
		/* 8 here is named pipe message mode. */
		ret = cli_write(cli->trans.np.cli, cli->trans.np.fnum,
				0x8, prs_data_p(&rpc_out), 0,
				(size_t)prs_offset(&rpc_out));
		break;

		if (ret != (ssize_t)prs_offset(&rpc_out)) {
			nt_status = cli_get_nt_error(cli->trans.np.cli);
		}
	case NCACN_IP_TCP:
	case NCACN_UNIX_STREAM:
		ret = write_data(cli->trans.sock.fd, prs_data_p(&rpc_out),
				 (size_t)prs_offset(&rpc_out));
		if (ret != (ssize_t)prs_offset(&rpc_out)) {
			nt_status = map_nt_error_from_unix(errno);
		}
		break;
	default:
		DEBUG(0, ("unknown transport type %d\n", cli->transport_type));
		return NT_STATUS_INTERNAL_ERROR;
	}

	if (ret != (ssize_t)prs_offset(&rpc_out)) {
		DEBUG(0,("rpc_send_auth_auth3: write failed. Return was %s\n",
			 nt_errstr(nt_status)));
		prs_mem_free(&rpc_out);
		data_blob_free(&client_reply);
		data_blob_free(&server_response);
		return nt_status;
	}

	DEBUG(5,("rpc_send_auth_auth3: %s sent auth3 response ok.\n",
		 rpccli_pipe_txt(debug_ctx(), cli)));

	prs_mem_free(&rpc_out);
	data_blob_free(&client_reply);
	data_blob_free(&server_response);
	return NT_STATUS_OK;
}

/*******************************************************************
 Creates a DCE/RPC bind alter context authentication request which
 may contain a spnego auth blobl
 ********************************************************************/

static NTSTATUS create_rpc_alter_context(uint32 rpc_call_id,
					const RPC_IFACE *abstract,
					const RPC_IFACE *transfer,
					enum pipe_auth_level auth_level,
					const DATA_BLOB *pauth_blob, /* spnego auth blob already created. */
					prs_struct *rpc_out)
{
	RPC_HDR_AUTH hdr_auth;
	prs_struct auth_info;
	NTSTATUS ret = NT_STATUS_OK;

	ZERO_STRUCT(hdr_auth);
	if (!prs_init(&auth_info, RPC_HDR_AUTH_LEN, prs_get_mem_context(rpc_out), MARSHALL))
		return NT_STATUS_NO_MEMORY;

	/* We may change the pad length before marshalling. */
	init_rpc_hdr_auth(&hdr_auth, RPC_SPNEGO_AUTH_TYPE, (int)auth_level, 0, 1);

	if (pauth_blob->length) {
		if (!prs_copy_data_in(&auth_info, (const char *)pauth_blob->data, pauth_blob->length)) {
			prs_mem_free(&auth_info);
			return NT_STATUS_NO_MEMORY;
		}
	}

	ret = create_bind_or_alt_ctx_internal(RPC_ALTCONT,
						rpc_out, 
						rpc_call_id,
						abstract,
						transfer,
						&hdr_auth,
						&auth_info);
	prs_mem_free(&auth_info);
	return ret;
}

/*******************************************************************
 Third leg of the SPNEGO bind mechanism - sends alter context PDU
 and gets a response.
 ********************************************************************/

static NTSTATUS rpc_finish_spnego_ntlmssp_bind(struct rpc_pipe_client *cli,
                                RPC_HDR *phdr,
                                prs_struct *rbuf,
                                uint32 rpc_call_id,
				const RPC_IFACE *abstract,
				const RPC_IFACE *transfer,
                                enum pipe_auth_type auth_type,
                                enum pipe_auth_level auth_level)
{
	DATA_BLOB server_spnego_response = data_blob_null;
	DATA_BLOB server_ntlm_response = data_blob_null;
	DATA_BLOB client_reply = data_blob_null;
	DATA_BLOB tmp_blob = data_blob_null;
	RPC_HDR_AUTH hdr_auth;
	NTSTATUS nt_status;
	prs_struct rpc_out;

	if (!phdr->auth_len || (phdr->frag_len < phdr->auth_len + RPC_HDR_AUTH_LEN)) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	/* Process the returned NTLMSSP blob first. */
	if (!prs_set_offset(rbuf, phdr->frag_len - phdr->auth_len - RPC_HDR_AUTH_LEN)) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if(!smb_io_rpc_hdr_auth("hdr_auth", &hdr_auth, rbuf, 0)) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	server_spnego_response = data_blob(NULL, phdr->auth_len);
	prs_copy_data_out((char *)server_spnego_response.data, rbuf, phdr->auth_len);

	/* The server might give us back two challenges - tmp_blob is for the second. */
	if (!spnego_parse_challenge(server_spnego_response, &server_ntlm_response, &tmp_blob)) {
		data_blob_free(&server_spnego_response);
		data_blob_free(&server_ntlm_response);
		data_blob_free(&tmp_blob);
		return NT_STATUS_INVALID_PARAMETER;
	}

	/* We're finished with the server spnego response and the tmp_blob. */
	data_blob_free(&server_spnego_response);
	data_blob_free(&tmp_blob);

	nt_status = ntlmssp_update(cli->auth->a_u.ntlmssp_state,
				   server_ntlm_response,
				   &client_reply);

	/* Finished with the server_ntlm response */
	data_blob_free(&server_ntlm_response);

	if (!NT_STATUS_IS_OK(nt_status)) {
		DEBUG(0,("rpc_finish_spnego_ntlmssp_bind: NTLMSSP update using server blob failed.\n"));
		data_blob_free(&client_reply);
		return nt_status;
	}

	/* SPNEGO wrap the client reply. */
	tmp_blob = spnego_gen_auth(client_reply);
	data_blob_free(&client_reply);
	client_reply = tmp_blob;
	tmp_blob = data_blob_null; /* Ensure it's safe to free this just in case. */

	/* Now prepare the alter context pdu. */
	prs_init_empty(&rpc_out, prs_get_mem_context(rbuf), MARSHALL);

	nt_status = create_rpc_alter_context(rpc_call_id,
						abstract,
						transfer,
						auth_level,
						&client_reply,
						&rpc_out);

	data_blob_free(&client_reply);

	if (!NT_STATUS_IS_OK(nt_status)) {
		prs_mem_free(&rpc_out);
		return nt_status;
	}

	/* Initialize the returning data struct. */
	prs_mem_free(rbuf);
	prs_init_empty(rbuf, talloc_tos(), UNMARSHALL);

	nt_status = rpc_api_pipe(cli, &rpc_out, rbuf, RPC_ALTCONTRESP);
	if (!NT_STATUS_IS_OK(nt_status)) {
		prs_mem_free(&rpc_out);
		return nt_status;
	}

	prs_mem_free(&rpc_out);

	/* Get the auth blob from the reply. */
	if(!smb_io_rpc_hdr("rpc_hdr   ", phdr, rbuf, 0)) {
		DEBUG(0,("rpc_finish_spnego_ntlmssp_bind: Failed to unmarshall RPC_HDR.\n"));
		return NT_STATUS_BUFFER_TOO_SMALL;
	}

	if (!prs_set_offset(rbuf, phdr->frag_len - phdr->auth_len - RPC_HDR_AUTH_LEN)) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if(!smb_io_rpc_hdr_auth("hdr_auth", &hdr_auth, rbuf, 0)) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	server_spnego_response = data_blob(NULL, phdr->auth_len);
	prs_copy_data_out((char *)server_spnego_response.data, rbuf, phdr->auth_len);

	/* Check we got a valid auth response. */
	if (!spnego_parse_auth_response(server_spnego_response, NT_STATUS_OK, OID_NTLMSSP, &tmp_blob)) {
		data_blob_free(&server_spnego_response);
		data_blob_free(&tmp_blob);
		return NT_STATUS_INVALID_PARAMETER;
	}

	data_blob_free(&server_spnego_response);
	data_blob_free(&tmp_blob);

	DEBUG(5,("rpc_finish_spnego_ntlmssp_bind: alter context request to "
		 "%s.\n", rpccli_pipe_txt(debug_ctx(), cli)));

	return NT_STATUS_OK;
}

/****************************************************************************
 Do an rpc bind.
****************************************************************************/

NTSTATUS rpc_pipe_bind(struct rpc_pipe_client *cli,
		       struct cli_pipe_auth_data *auth)
{
	RPC_HDR hdr;
	RPC_HDR_BA hdr_ba;
	prs_struct rpc_out;
	prs_struct rbuf;
	uint32 rpc_call_id;
	NTSTATUS status;

	DEBUG(5,("Bind RPC Pipe: %s auth_type %u, auth_level %u\n",
		rpccli_pipe_txt(debug_ctx(), cli),
		(unsigned int)auth->auth_type,
		(unsigned int)auth->auth_level ));

	cli->auth = talloc_move(cli, &auth);

	prs_init_empty(&rpc_out, talloc_tos(), MARSHALL);

	rpc_call_id = get_rpc_call_id();

	/* Marshall the outgoing data. */
	status = create_rpc_bind_req(cli, &rpc_out, rpc_call_id,
				&cli->abstract_syntax,
				&cli->transfer_syntax,
				cli->auth->auth_type,
				cli->auth->auth_level);

	if (!NT_STATUS_IS_OK(status)) {
		prs_mem_free(&rpc_out);
		return status;
	}

	/* Initialize the incoming data struct. */
	prs_init_empty(&rbuf, talloc_tos(), UNMARSHALL);

	/* send data on \PIPE\.  receive a response */
	status = rpc_api_pipe(cli, &rpc_out, &rbuf, RPC_BINDACK);
	if (!NT_STATUS_IS_OK(status)) {
		prs_mem_free(&rpc_out);
		return status;
	}

	prs_mem_free(&rpc_out);

	DEBUG(3,("rpc_pipe_bind: %s bind request returned ok.\n",
		 rpccli_pipe_txt(debug_ctx(), cli)));

	/* Unmarshall the RPC header */
	if(!smb_io_rpc_hdr("hdr"   , &hdr, &rbuf, 0)) {
		DEBUG(0,("rpc_pipe_bind: failed to unmarshall RPC_HDR.\n"));
		prs_mem_free(&rbuf);
		return NT_STATUS_BUFFER_TOO_SMALL;
	}

	if(!smb_io_rpc_hdr_ba("", &hdr_ba, &rbuf, 0)) {
		DEBUG(0,("rpc_pipe_bind: Failed to unmarshall RPC_HDR_BA.\n"));
		prs_mem_free(&rbuf);
		return NT_STATUS_BUFFER_TOO_SMALL;
	}

	if(!check_bind_response(&hdr_ba, &cli->transfer_syntax)) {
		DEBUG(2,("rpc_pipe_bind: check_bind_response failed.\n"));
		prs_mem_free(&rbuf);
		return NT_STATUS_BUFFER_TOO_SMALL;
	}

	cli->max_xmit_frag = hdr_ba.bba.max_tsize;
	cli->max_recv_frag = hdr_ba.bba.max_rsize;

	/* For authenticated binds we may need to do 3 or 4 leg binds. */
	switch(cli->auth->auth_type) {

		case PIPE_AUTH_TYPE_NONE:
		case PIPE_AUTH_TYPE_SCHANNEL:
			/* Bind complete. */
			break;

		case PIPE_AUTH_TYPE_NTLMSSP:
			/* Need to send AUTH3 packet - no reply. */
			status = rpc_finish_auth3_bind(
				cli, &hdr, &rbuf, rpc_call_id,
				cli->auth->auth_type,
				cli->auth->auth_level);
			if (!NT_STATUS_IS_OK(status)) {
				prs_mem_free(&rbuf);
				return status;
			}
			break;

		case PIPE_AUTH_TYPE_SPNEGO_NTLMSSP:
			/* Need to send alter context request and reply. */
			status = rpc_finish_spnego_ntlmssp_bind(
				cli, &hdr, &rbuf, rpc_call_id,
				&cli->abstract_syntax, &cli->transfer_syntax,
				cli->auth->auth_type, cli->auth->auth_level);
			if (!NT_STATUS_IS_OK(status)) {
				prs_mem_free(&rbuf);
				return status;
			}
			break;

		case PIPE_AUTH_TYPE_KRB5:
			/* */

		default:
			DEBUG(0,("cli_finish_bind_auth: unknown auth type "
				 "%u\n", (unsigned int)cli->auth->auth_type));
			prs_mem_free(&rbuf);
			return NT_STATUS_INVALID_INFO_CLASS;
	}

	/* For NTLMSSP ensure the server gave us the auth_level we wanted. */
	if (cli->auth->auth_type == PIPE_AUTH_TYPE_NTLMSSP
	    || cli->auth->auth_type == PIPE_AUTH_TYPE_SPNEGO_NTLMSSP) {
		if (cli->auth->auth_level == PIPE_AUTH_LEVEL_INTEGRITY) {
			if (!(cli->auth->a_u.ntlmssp_state->neg_flags & NTLMSSP_NEGOTIATE_SIGN)) {
				DEBUG(0,("cli_finish_bind_auth: requested NTLMSSSP signing and server refused.\n"));
				prs_mem_free(&rbuf);
				return NT_STATUS_INVALID_PARAMETER;
			}
		}
		if (cli->auth->auth_level == PIPE_AUTH_LEVEL_INTEGRITY) {
			if (!(cli->auth->a_u.ntlmssp_state->neg_flags & NTLMSSP_NEGOTIATE_SEAL)) {
				DEBUG(0,("cli_finish_bind_auth: requested NTLMSSSP sealing and server refused.\n"));
				prs_mem_free(&rbuf);
				return NT_STATUS_INVALID_PARAMETER;
			}
		}
	}

	prs_mem_free(&rbuf);
	return NT_STATUS_OK;
}

unsigned int rpccli_set_timeout(struct rpc_pipe_client *cli,
				unsigned int timeout)
{
	return cli_set_timeout(cli->trans.np.cli, timeout);
}

bool rpccli_get_pwd_hash(struct rpc_pipe_client *cli, uint8_t nt_hash[16])
{
	if ((cli->auth->auth_type == PIPE_AUTH_TYPE_NTLMSSP)
	    || (cli->auth->auth_type == PIPE_AUTH_TYPE_SPNEGO_NTLMSSP)) {
		memcpy(nt_hash, cli->auth->a_u.ntlmssp_state->nt_hash, 16);
		return true;
	}

	if (cli->transport_type == NCACN_NP) {
		E_md4hash(cli->trans.np.cli->pwd.password, nt_hash);
		return true;
	}

	return false;
}

struct cli_state *rpc_pipe_np_smb_conn(struct rpc_pipe_client *p)
{
	if (p->transport_type == NCACN_NP) {
		return p->trans.np.cli;
	}
	return NULL;
}

static int rpc_pipe_destructor(struct rpc_pipe_client *p)
{
	if (p->transport_type == NCACN_NP) {
		bool ret;
		ret = cli_close(p->trans.np.cli, p->trans.np.fnum);
		if (!ret) {
			DEBUG(1, ("rpc_pipe_destructor: cli_close failed on "
				  "pipe %s. Error was %s\n",
				  rpccli_pipe_txt(debug_ctx(), p),
				  cli_errstr(p->trans.np.cli)));
		}

		DEBUG(10, ("rpc_pipe_destructor: closed %s\n",
			   rpccli_pipe_txt(debug_ctx(), p)));

		DLIST_REMOVE(p->trans.np.cli->pipe_list, p);
		return ret ? -1 : 0;
	}

	return -1;
}

NTSTATUS rpccli_anon_bind_data(TALLOC_CTX *mem_ctx,
			       struct cli_pipe_auth_data **presult)
{
	struct cli_pipe_auth_data *result;

	result = talloc(mem_ctx, struct cli_pipe_auth_data);
	if (result == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	result->auth_type = PIPE_AUTH_TYPE_NONE;
	result->auth_level = PIPE_AUTH_LEVEL_NONE;

	result->user_name = talloc_strdup(result, "");
	result->domain = talloc_strdup(result, "");
	if ((result->user_name == NULL) || (result->domain == NULL)) {
		TALLOC_FREE(result);
		return NT_STATUS_NO_MEMORY;
	}

	*presult = result;
	return NT_STATUS_OK;
}

static int cli_auth_ntlmssp_data_destructor(struct cli_pipe_auth_data *auth)
{
	ntlmssp_end(&auth->a_u.ntlmssp_state);
	return 0;
}

NTSTATUS rpccli_ntlmssp_bind_data(TALLOC_CTX *mem_ctx,
				  enum pipe_auth_type auth_type,
				  enum pipe_auth_level auth_level,
				  const char *domain,
				  const char *username,
				  const char *password,
				  struct cli_pipe_auth_data **presult)
{
	struct cli_pipe_auth_data *result;
	NTSTATUS status;

	result = talloc(mem_ctx, struct cli_pipe_auth_data);
	if (result == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	result->auth_type = auth_type;
	result->auth_level = auth_level;

	result->user_name = talloc_strdup(result, username);
	result->domain = talloc_strdup(result, domain);
	if ((result->user_name == NULL) || (result->domain == NULL)) {
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}

	status = ntlmssp_client_start(&result->a_u.ntlmssp_state);
	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}

	talloc_set_destructor(result, cli_auth_ntlmssp_data_destructor);

	status = ntlmssp_set_username(result->a_u.ntlmssp_state, username);
	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}

	status = ntlmssp_set_domain(result->a_u.ntlmssp_state, domain);
	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}

	status = ntlmssp_set_password(result->a_u.ntlmssp_state, password);
	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}

	/*
	 * Turn off sign+seal to allow selected auth level to turn it back on.
	 */
	result->a_u.ntlmssp_state->neg_flags &=
		~(NTLMSSP_NEGOTIATE_SIGN | NTLMSSP_NEGOTIATE_SEAL);

	if (auth_level == PIPE_AUTH_LEVEL_INTEGRITY) {
		result->a_u.ntlmssp_state->neg_flags |= NTLMSSP_NEGOTIATE_SIGN;
	} else if (auth_level == PIPE_AUTH_LEVEL_PRIVACY) {
		result->a_u.ntlmssp_state->neg_flags
			|= NTLMSSP_NEGOTIATE_SEAL | NTLMSSP_NEGOTIATE_SIGN;
	}

	*presult = result;
	return NT_STATUS_OK;

 fail:
	TALLOC_FREE(result);
	return status;
}

NTSTATUS rpccli_schannel_bind_data(TALLOC_CTX *mem_ctx, const char *domain,
				   enum pipe_auth_level auth_level,
				   const uint8_t sess_key[16],
				   struct cli_pipe_auth_data **presult)
{
	struct cli_pipe_auth_data *result;

	result = talloc(mem_ctx, struct cli_pipe_auth_data);
	if (result == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	result->auth_type = PIPE_AUTH_TYPE_SCHANNEL;
	result->auth_level = auth_level;

	result->user_name = talloc_strdup(result, "");
	result->domain = talloc_strdup(result, domain);
	if ((result->user_name == NULL) || (result->domain == NULL)) {
		goto fail;
	}

	result->a_u.schannel_auth = talloc(result,
					   struct schannel_auth_struct);
	if (result->a_u.schannel_auth == NULL) {
		goto fail;
	}

	memcpy(result->a_u.schannel_auth->sess_key, sess_key,
	       sizeof(result->a_u.schannel_auth->sess_key));
	result->a_u.schannel_auth->seq_num = 0;

	*presult = result;
	return NT_STATUS_OK;

 fail:
	TALLOC_FREE(result);
	return NT_STATUS_NO_MEMORY;
}

#ifdef HAVE_KRB5
static int cli_auth_kerberos_data_destructor(struct kerberos_auth_struct *auth)
{
	data_blob_free(&auth->session_key);
	return 0;
}
#endif

NTSTATUS rpccli_kerberos_bind_data(TALLOC_CTX *mem_ctx,
				   enum pipe_auth_level auth_level,
				   const char *service_princ,
				   const char *username,
				   const char *password,
				   struct cli_pipe_auth_data **presult)
{
#ifdef HAVE_KRB5
	struct cli_pipe_auth_data *result;

	if ((username != NULL) && (password != NULL)) {
		int ret = kerberos_kinit_password(username, password, 0, NULL);
		if (ret != 0) {
			return NT_STATUS_ACCESS_DENIED;
		}
	}

	result = talloc(mem_ctx, struct cli_pipe_auth_data);
	if (result == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	result->auth_type = PIPE_AUTH_TYPE_KRB5;
	result->auth_level = auth_level;

	/*
	 * Username / domain need fixing!
	 */
	result->user_name = talloc_strdup(result, "");
	result->domain = talloc_strdup(result, "");
	if ((result->user_name == NULL) || (result->domain == NULL)) {
		goto fail;
	}

	result->a_u.kerberos_auth = TALLOC_ZERO_P(
		result, struct kerberos_auth_struct);
	if (result->a_u.kerberos_auth == NULL) {
		goto fail;
	}
	talloc_set_destructor(result->a_u.kerberos_auth,
			      cli_auth_kerberos_data_destructor);

	result->a_u.kerberos_auth->service_principal = talloc_strdup(
		result, service_princ);
	if (result->a_u.kerberos_auth->service_principal == NULL) {
		goto fail;
	}

	*presult = result;
	return NT_STATUS_OK;

 fail:
	TALLOC_FREE(result);
	return NT_STATUS_NO_MEMORY;
#else
	return NT_STATUS_NOT_SUPPORTED;
#endif
}

static int rpc_pipe_sock_destructor(struct rpc_pipe_client *p)
{
	close(p->trans.sock.fd);
	return 0;
}

/**
 * Create an rpc pipe client struct, connecting to a tcp port.
 */
static NTSTATUS rpc_pipe_open_tcp_port(TALLOC_CTX *mem_ctx, const char *host,
				       uint16_t port,
				       const struct ndr_syntax_id *abstract_syntax,
				       struct rpc_pipe_client **presult)
{
	struct rpc_pipe_client *result;
	struct sockaddr_storage addr;
	NTSTATUS status;

	result = TALLOC_ZERO_P(mem_ctx, struct rpc_pipe_client);
	if (result == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	result->transport_type = NCACN_IP_TCP;

	result->abstract_syntax = *abstract_syntax;
	result->transfer_syntax = ndr_transfer_syntax;

	result->desthost = talloc_strdup(result, host);
	result->srv_name_slash = talloc_asprintf_strupper_m(
		result, "\\\\%s", result->desthost);
	if ((result->desthost == NULL) || (result->srv_name_slash == NULL)) {
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}

	result->max_xmit_frag = RPC_MAX_PDU_FRAG_LEN;
	result->max_recv_frag = RPC_MAX_PDU_FRAG_LEN;

	if (!resolve_name(host, &addr, 0)) {
		status = NT_STATUS_NOT_FOUND;
		goto fail;
	}

	result->trans.sock.fd = open_socket_out(SOCK_STREAM, &addr, port, 60);
	if (result->trans.sock.fd == -1) {
		status = map_nt_error_from_unix(errno);
		goto fail;
	}

	talloc_set_destructor(result, rpc_pipe_sock_destructor);

	*presult = result;
	return NT_STATUS_OK;

 fail:
	TALLOC_FREE(result);
	return status;
}

/**
 * Determine the tcp port on which a dcerpc interface is listening
 * for the ncacn_ip_tcp transport via the endpoint mapper of the
 * target host.
 */
static NTSTATUS rpc_pipe_get_tcp_port(const char *host,
				      const struct ndr_syntax_id *abstract_syntax,
				      uint16_t *pport)
{
	NTSTATUS status;
	struct rpc_pipe_client *epm_pipe = NULL;
	struct cli_pipe_auth_data *auth = NULL;
	struct dcerpc_binding *map_binding = NULL;
	struct dcerpc_binding *res_binding = NULL;
	struct epm_twr_t *map_tower = NULL;
	struct epm_twr_t *res_towers = NULL;
	struct policy_handle *entry_handle = NULL;
	uint32_t num_towers = 0;
	uint32_t max_towers = 1;
	struct epm_twr_p_t towers;
	TALLOC_CTX *tmp_ctx = talloc_stackframe();

	if (pport == NULL) {
		status = NT_STATUS_INVALID_PARAMETER;
		goto done;
	}

	/* open the connection to the endpoint mapper */
	status = rpc_pipe_open_tcp_port(tmp_ctx, host, 135,
					&ndr_table_epmapper.syntax_id,
					&epm_pipe);

	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

	status = rpccli_anon_bind_data(tmp_ctx, &auth);
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

	status = rpc_pipe_bind(epm_pipe, auth);
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

	/* create tower for asking the epmapper */

	map_binding = TALLOC_ZERO_P(tmp_ctx, struct dcerpc_binding);
	if (map_binding == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}

	map_binding->transport = NCACN_IP_TCP;
	map_binding->object = *abstract_syntax;
	map_binding->host = host; /* needed? */
	map_binding->endpoint = "0"; /* correct? needed? */

	map_tower = TALLOC_ZERO_P(tmp_ctx, struct epm_twr_t);
	if (map_tower == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}

	status = dcerpc_binding_build_tower(tmp_ctx, map_binding,
					    &(map_tower->tower));
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

	/* allocate further parameters for the epm_Map call */

	res_towers = TALLOC_ARRAY(tmp_ctx, struct epm_twr_t, max_towers);
	if (res_towers == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}
	towers.twr = res_towers;

	entry_handle = TALLOC_ZERO_P(tmp_ctx, struct policy_handle);
	if (entry_handle == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}

	/* ask the endpoint mapper for the port */

	status = rpccli_epm_Map(epm_pipe,
				tmp_ctx,
				CONST_DISCARD(struct GUID *,
					      &(abstract_syntax->uuid)),
				map_tower,
				entry_handle,
				max_towers,
				&num_towers,
				&towers);

	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

	if (num_towers != 1) {
		status = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	/* extract the port from the answer */

	status = dcerpc_binding_from_tower(tmp_ctx,
					   &(towers.twr->tower),
					   &res_binding);
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

	/* are further checks here necessary? */
	if (res_binding->transport != NCACN_IP_TCP) {
		status = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	*pport = (uint16_t)atoi(res_binding->endpoint);

done:
	TALLOC_FREE(tmp_ctx);
	return status;
}

/**
 * Create a rpc pipe client struct, connecting to a host via tcp.
 * The port is determined by asking the endpoint mapper on the given
 * host.
 */
NTSTATUS rpc_pipe_open_tcp(TALLOC_CTX *mem_ctx, const char *host,
			   const struct ndr_syntax_id *abstract_syntax,
			   struct rpc_pipe_client **presult)
{
	NTSTATUS status;
	uint16_t port = 0;

	*presult = NULL;

	status = rpc_pipe_get_tcp_port(host, abstract_syntax, &port);
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

	status = rpc_pipe_open_tcp_port(mem_ctx, host, port,
					abstract_syntax, presult);

done:
	return status;
}

/********************************************************************
 Create a rpc pipe client struct, connecting to a unix domain socket
 ********************************************************************/
NTSTATUS rpc_pipe_open_ncalrpc(TALLOC_CTX *mem_ctx, const char *socket_path,
			       const struct ndr_syntax_id *abstract_syntax,
			       struct rpc_pipe_client **presult)
{
	struct rpc_pipe_client *result;
	struct sockaddr_un addr;
	NTSTATUS status;

	result = talloc_zero(mem_ctx, struct rpc_pipe_client);
	if (result == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	result->transport_type = NCACN_UNIX_STREAM;

	result->abstract_syntax = *abstract_syntax;
	result->transfer_syntax = ndr_transfer_syntax;

	result->desthost = get_myname(result);
	result->srv_name_slash = talloc_asprintf_strupper_m(
		result, "\\\\%s", result->desthost);
	if ((result->desthost == NULL) || (result->srv_name_slash == NULL)) {
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}

	result->max_xmit_frag = RPC_MAX_PDU_FRAG_LEN;
	result->max_recv_frag = RPC_MAX_PDU_FRAG_LEN;

	result->trans.sock.fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (result->trans.sock.fd == -1) {
		status = map_nt_error_from_unix(errno);
		goto fail;
	}

	talloc_set_destructor(result, rpc_pipe_sock_destructor);

	ZERO_STRUCT(addr);
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path));

	if (sys_connect(result->trans.sock.fd,
			(struct sockaddr *)&addr) == -1) {
		DEBUG(0, ("connect(%s) failed: %s\n", socket_path,
			  strerror(errno)));
		close(result->trans.sock.fd);
		return map_nt_error_from_unix(errno);
	}

	*presult = result;
	return NT_STATUS_OK;

 fail:
	TALLOC_FREE(result);
	return status;
}


/****************************************************************************
 Open a named pipe over SMB to a remote server.
 *
 * CAVEAT CALLER OF THIS FUNCTION:
 *    The returned rpc_pipe_client saves a copy of the cli_state cli pointer,
 *    so be sure that this function is called AFTER any structure (vs pointer)
 *    assignment of the cli.  In particular, libsmbclient does structure
 *    assignments of cli, which invalidates the data in the returned
 *    rpc_pipe_client if this function is called before the structure assignment
 *    of cli.
 * 
 ****************************************************************************/

static NTSTATUS rpc_pipe_open_np(struct cli_state *cli,
				 const struct ndr_syntax_id *abstract_syntax,
				 struct rpc_pipe_client **presult)
{
	struct rpc_pipe_client *result;
	int fnum;

	/* sanity check to protect against crashes */

	if ( !cli ) {
		return NT_STATUS_INVALID_HANDLE;
	}

	result = TALLOC_ZERO_P(NULL, struct rpc_pipe_client);
	if (result == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	result->transport_type = NCACN_NP;

	result->trans.np.pipe_name = cli_get_pipe_name_from_iface(
		result, cli, abstract_syntax);
	if (result->trans.np.pipe_name == NULL) {
		DEBUG(1, ("Could not find pipe for interface\n"));
		TALLOC_FREE(result);
		return NT_STATUS_INVALID_PARAMETER;
	}

	result->trans.np.cli = cli;
	result->abstract_syntax = *abstract_syntax;
	result->transfer_syntax = ndr_transfer_syntax;
	result->desthost = talloc_strdup(result, cli->desthost);
	result->srv_name_slash = talloc_asprintf_strupper_m(
		result, "\\\\%s", result->desthost);

	if ((result->desthost == NULL) || (result->srv_name_slash == NULL)) {
		TALLOC_FREE(result);
		return NT_STATUS_NO_MEMORY;
	}

	fnum = cli_nt_create(cli, result->trans.np.pipe_name,
			     DESIRED_ACCESS_PIPE);
	if (fnum == -1) {
		DEBUG(3,("rpc_pipe_open_np: cli_nt_create failed on pipe %s "
			 "to machine %s.  Error was %s\n",
			 result->trans.np.pipe_name, cli->desthost,
			 cli_errstr(cli)));
		TALLOC_FREE(result);
		return cli_get_nt_error(cli);
	}

	result->trans.np.fnum = fnum;

	DLIST_ADD(cli->pipe_list, result);
	talloc_set_destructor(result, rpc_pipe_destructor);

	*presult = result;
	return NT_STATUS_OK;
}

/****************************************************************************
 Open a pipe to a remote server.
 ****************************************************************************/

static NTSTATUS cli_rpc_pipe_open(struct cli_state *cli,
				  const struct ndr_syntax_id *interface,
				  struct rpc_pipe_client **presult)
{
	if (ndr_syntax_id_equal(interface, &ndr_table_drsuapi.syntax_id)) {
		/*
		 * We should have a better way to figure out this drsuapi
		 * speciality...
		 */
		return rpc_pipe_open_tcp(NULL, cli->desthost, interface,
					 presult);
	}

	return rpc_pipe_open_np(cli, interface, presult);
}

/****************************************************************************
 Open a named pipe to an SMB server and bind anonymously.
 ****************************************************************************/

NTSTATUS cli_rpc_pipe_open_noauth(struct cli_state *cli,
				  const struct ndr_syntax_id *interface,
				  struct rpc_pipe_client **presult)
{
	struct rpc_pipe_client *result;
	struct cli_pipe_auth_data *auth;
	NTSTATUS status;

	status = cli_rpc_pipe_open(cli, interface, &result);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	status = rpccli_anon_bind_data(result, &auth);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("rpccli_anon_bind_data returned %s\n",
			  nt_errstr(status)));
		TALLOC_FREE(result);
		return status;
	}

	/*
	 * This is a bit of an abstraction violation due to the fact that an
	 * anonymous bind on an authenticated SMB inherits the user/domain
	 * from the enclosing SMB creds
	 */

	TALLOC_FREE(auth->user_name);
	TALLOC_FREE(auth->domain);

	auth->user_name = talloc_strdup(auth, cli->user_name);
	auth->domain = talloc_strdup(auth, cli->domain);

	if ((auth->user_name == NULL) || (auth->domain == NULL)) {
		TALLOC_FREE(result);
		return NT_STATUS_NO_MEMORY;
	}

	status = rpc_pipe_bind(result, auth);
	if (!NT_STATUS_IS_OK(status)) {
		int lvl = 0;
		if (ndr_syntax_id_equal(interface,
					&ndr_table_dssetup.syntax_id)) {
			/* non AD domains just don't have this pipe, avoid
			 * level 0 statement in that case - gd */
			lvl = 3;
		}
		DEBUG(lvl, ("cli_rpc_pipe_open_noauth: rpc_pipe_bind for pipe "
			    "%s failed with error %s\n",
			    cli_get_pipe_name_from_iface(debug_ctx(), cli,
							 interface),
			    nt_errstr(status) ));
		TALLOC_FREE(result);
		return status;
	}

	DEBUG(10,("cli_rpc_pipe_open_noauth: opened pipe %s to machine "
		  "%s and bound anonymously.\n", result->trans.np.pipe_name,
		  cli->desthost ));

	*presult = result;
	return NT_STATUS_OK;
}

/****************************************************************************
 Open a named pipe to an SMB server and bind using NTLMSSP or SPNEGO NTLMSSP
 ****************************************************************************/

static NTSTATUS cli_rpc_pipe_open_ntlmssp_internal(struct cli_state *cli,
						   const struct ndr_syntax_id *interface,
						   enum pipe_auth_type auth_type,
						   enum pipe_auth_level auth_level,
						   const char *domain,
						   const char *username,
						   const char *password,
						   struct rpc_pipe_client **presult)
{
	struct rpc_pipe_client *result;
	struct cli_pipe_auth_data *auth;
	NTSTATUS status;

	status = cli_rpc_pipe_open(cli, interface, &result);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	status = rpccli_ntlmssp_bind_data(
		result, auth_type, auth_level, domain, username,
		cli->pwd.null_pwd ? NULL : password, &auth);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("rpccli_ntlmssp_bind_data returned %s\n",
			  nt_errstr(status)));
		goto err;
	}

	status = rpc_pipe_bind(result, auth);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("cli_rpc_pipe_open_ntlmssp_internal: cli_rpc_pipe_bind failed with error %s\n",
			nt_errstr(status) ));
		goto err;
	}

	DEBUG(10,("cli_rpc_pipe_open_ntlmssp_internal: opened pipe %s to "
		"machine %s and bound NTLMSSP as user %s\\%s.\n",
		result->trans.np.pipe_name, cli->desthost,
		domain, username ));

	*presult = result;
	return NT_STATUS_OK;

  err:

	TALLOC_FREE(result);
	return status;
}

/****************************************************************************
 External interface.
 Open a named pipe to an SMB server and bind using NTLMSSP (bind type 10)
 ****************************************************************************/

NTSTATUS cli_rpc_pipe_open_ntlmssp(struct cli_state *cli,
				   const struct ndr_syntax_id *interface,
				   enum pipe_auth_level auth_level,
				   const char *domain,
				   const char *username,
				   const char *password,
				   struct rpc_pipe_client **presult)
{
	return cli_rpc_pipe_open_ntlmssp_internal(cli,
						interface,
						PIPE_AUTH_TYPE_NTLMSSP,
						auth_level,
						domain,
						username,
						password,
						presult);
}

/****************************************************************************
 External interface.
 Open a named pipe to an SMB server and bind using spnego NTLMSSP (bind type 9)
 ****************************************************************************/

NTSTATUS cli_rpc_pipe_open_spnego_ntlmssp(struct cli_state *cli,
					  const struct ndr_syntax_id *interface,
					  enum pipe_auth_level auth_level,
					  const char *domain,
					  const char *username,
					  const char *password,
					  struct rpc_pipe_client **presult)
{
	return cli_rpc_pipe_open_ntlmssp_internal(cli,
						interface,
						PIPE_AUTH_TYPE_SPNEGO_NTLMSSP,
						auth_level,
						domain,
						username,
						password,
						presult);
}

/****************************************************************************
  Get a the schannel session key out of an already opened netlogon pipe.
 ****************************************************************************/
static NTSTATUS get_schannel_session_key_common(struct rpc_pipe_client *netlogon_pipe,
						struct cli_state *cli,
						const char *domain,
						uint32 *pneg_flags)
{
	uint32 sec_chan_type = 0;
	unsigned char machine_pwd[16];
	const char *machine_account;
	NTSTATUS status;

	/* Get the machine account credentials from secrets.tdb. */
	if (!get_trust_pw_hash(domain, machine_pwd, &machine_account,
			       &sec_chan_type))
	{
		DEBUG(0, ("get_schannel_session_key: could not fetch "
			"trust account password for domain '%s'\n",
			domain));
		return NT_STATUS_CANT_ACCESS_DOMAIN_INFO;
	}

	status = rpccli_netlogon_setup_creds(netlogon_pipe,
					cli->desthost, /* server name */
					domain,	       /* domain */
					global_myname(), /* client name */
					machine_account, /* machine account name */
					machine_pwd,
					sec_chan_type,
					pneg_flags);

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(3, ("get_schannel_session_key_common: "
			  "rpccli_netlogon_setup_creds failed with result %s "
			  "to server %s, domain %s, machine account %s.\n",
			  nt_errstr(status), cli->desthost, domain,
			  machine_account ));
		return status;
	}

	if (((*pneg_flags) & NETLOGON_NEG_SCHANNEL) == 0) {
		DEBUG(3, ("get_schannel_session_key: Server %s did not offer schannel\n",
			cli->desthost));
		return NT_STATUS_INVALID_NETWORK_RESPONSE;
	}

	return NT_STATUS_OK;;
}

/****************************************************************************
 Open a netlogon pipe and get the schannel session key.
 Now exposed to external callers.
 ****************************************************************************/


NTSTATUS get_schannel_session_key(struct cli_state *cli,
				  const char *domain,
				  uint32 *pneg_flags,
				  struct rpc_pipe_client **presult)
{
	struct rpc_pipe_client *netlogon_pipe = NULL;
	NTSTATUS status;

	status = cli_rpc_pipe_open_noauth(cli, &ndr_table_netlogon.syntax_id,
					  &netlogon_pipe);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	status = get_schannel_session_key_common(netlogon_pipe, cli, domain,
						 pneg_flags);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(netlogon_pipe);
		return status;
	}

	*presult = netlogon_pipe;
	return NT_STATUS_OK;
}

/****************************************************************************
 External interface.
 Open a named pipe to an SMB server and bind using schannel (bind type 68)
 using session_key. sign and seal.
 ****************************************************************************/

NTSTATUS cli_rpc_pipe_open_schannel_with_key(struct cli_state *cli,
					     const struct ndr_syntax_id *interface,
					     enum pipe_auth_level auth_level,
					     const char *domain,
					     const struct dcinfo *pdc,
					     struct rpc_pipe_client **presult)
{
	struct rpc_pipe_client *result;
	struct cli_pipe_auth_data *auth;
	NTSTATUS status;

	status = cli_rpc_pipe_open(cli, interface, &result);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	status = rpccli_schannel_bind_data(result, domain, auth_level,
					   pdc->sess_key, &auth);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("rpccli_schannel_bind_data returned %s\n",
			  nt_errstr(status)));
		TALLOC_FREE(result);
		return status;
	}

	status = rpc_pipe_bind(result, auth);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("cli_rpc_pipe_open_schannel_with_key: "
			  "cli_rpc_pipe_bind failed with error %s\n",
			  nt_errstr(status) ));
		TALLOC_FREE(result);
		return status;
	}

	/*
	 * The credentials on a new netlogon pipe are the ones we are passed
	 * in - copy them over.
	 */
	result->dc = (struct dcinfo *)talloc_memdup(result, pdc, sizeof(*pdc));
	if (result->dc == NULL) {
		DEBUG(0, ("talloc failed\n"));
		TALLOC_FREE(result);
		return NT_STATUS_NO_MEMORY;
	}

	DEBUG(10,("cli_rpc_pipe_open_schannel_with_key: opened pipe %s to machine %s "
		"for domain %s "
		"and bound using schannel.\n",
		result->trans.np.pipe_name, cli->desthost, domain ));

	*presult = result;
	return NT_STATUS_OK;
}

/****************************************************************************
 Open a named pipe to an SMB server and bind using schannel (bind type 68).
 Fetch the session key ourselves using a temporary netlogon pipe. This
 version uses an ntlmssp auth bound netlogon pipe to get the key.
 ****************************************************************************/

static NTSTATUS get_schannel_session_key_auth_ntlmssp(struct cli_state *cli,
						      const char *domain,
						      const char *username,
						      const char *password,
						      uint32 *pneg_flags,
						      struct rpc_pipe_client **presult)
{
	struct rpc_pipe_client *netlogon_pipe = NULL;
	NTSTATUS status;

	status = cli_rpc_pipe_open_spnego_ntlmssp(
		cli, &ndr_table_netlogon.syntax_id, PIPE_AUTH_LEVEL_PRIVACY,
		domain, username, password, &netlogon_pipe);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	status = get_schannel_session_key_common(netlogon_pipe, cli, domain,
						 pneg_flags);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(netlogon_pipe);
		return status;
	}

	*presult = netlogon_pipe;
	return NT_STATUS_OK;
}

/****************************************************************************
 Open a named pipe to an SMB server and bind using schannel (bind type 68).
 Fetch the session key ourselves using a temporary netlogon pipe. This version
 uses an ntlmssp bind to get the session key.
 ****************************************************************************/

NTSTATUS cli_rpc_pipe_open_ntlmssp_auth_schannel(struct cli_state *cli,
						 const struct ndr_syntax_id *interface,
						 enum pipe_auth_level auth_level,
						 const char *domain,
						 const char *username,
						 const char *password,
						 struct rpc_pipe_client **presult)
{
	uint32_t neg_flags = NETLOGON_NEG_AUTH2_ADS_FLAGS;
	struct rpc_pipe_client *netlogon_pipe = NULL;
	struct rpc_pipe_client *result = NULL;
	NTSTATUS status;

	status = get_schannel_session_key_auth_ntlmssp(
		cli, domain, username, password, &neg_flags, &netlogon_pipe);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("cli_rpc_pipe_open_ntlmssp_auth_schannel: failed to get schannel session "
			"key from server %s for domain %s.\n",
			cli->desthost, domain ));
		return status;
	}

	status = cli_rpc_pipe_open_schannel_with_key(
		cli, interface, auth_level, domain, netlogon_pipe->dc,
		&result);

	/* Now we've bound using the session key we can close the netlog pipe. */
	TALLOC_FREE(netlogon_pipe);

	if (NT_STATUS_IS_OK(status)) {
		*presult = result;
	}
	return status;
}

/****************************************************************************
 Open a named pipe to an SMB server and bind using schannel (bind type 68).
 Fetch the session key ourselves using a temporary netlogon pipe.
 ****************************************************************************/

NTSTATUS cli_rpc_pipe_open_schannel(struct cli_state *cli,
				    const struct ndr_syntax_id *interface,
				    enum pipe_auth_level auth_level,
				    const char *domain,
				    struct rpc_pipe_client **presult)
{
	uint32_t neg_flags = NETLOGON_NEG_AUTH2_ADS_FLAGS;
	struct rpc_pipe_client *netlogon_pipe = NULL;
	struct rpc_pipe_client *result = NULL;
	NTSTATUS status;

	status = get_schannel_session_key(cli, domain, &neg_flags,
					  &netlogon_pipe);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("cli_rpc_pipe_open_schannel: failed to get schannel session "
			"key from server %s for domain %s.\n",
			cli->desthost, domain ));
		return status;
	}

	status = cli_rpc_pipe_open_schannel_with_key(
		cli, interface, auth_level, domain, netlogon_pipe->dc,
		&result);

	/* Now we've bound using the session key we can close the netlog pipe. */
	TALLOC_FREE(netlogon_pipe);

	if (NT_STATUS_IS_OK(status)) {
		*presult = result;
	}

	return NT_STATUS_OK;
}

/****************************************************************************
 Open a named pipe to an SMB server and bind using krb5 (bind type 16).
 The idea is this can be called with service_princ, username and password all
 NULL so long as the caller has a TGT.
 ****************************************************************************/

NTSTATUS cli_rpc_pipe_open_krb5(struct cli_state *cli,
				const struct ndr_syntax_id *interface,
				enum pipe_auth_level auth_level,
				const char *service_princ,
				const char *username,
				const char *password,
				struct rpc_pipe_client **presult)
{
#ifdef HAVE_KRB5
	struct rpc_pipe_client *result;
	struct cli_pipe_auth_data *auth;
	NTSTATUS status;

	status = cli_rpc_pipe_open(cli, interface, &result);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	status = rpccli_kerberos_bind_data(result, auth_level, service_princ,
					   username, password, &auth);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("rpccli_kerberos_bind_data returned %s\n",
			  nt_errstr(status)));
		TALLOC_FREE(result);
		return status;
	}

	status = rpc_pipe_bind(result, auth);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("cli_rpc_pipe_open_krb5: cli_rpc_pipe_bind failed "
			  "with error %s\n", nt_errstr(status)));
		TALLOC_FREE(result);
		return status;
	}

	*presult = result;
	return NT_STATUS_OK;
#else
	DEBUG(0,("cli_rpc_pipe_open_krb5: kerberos not found at compile time.\n"));
	return NT_STATUS_NOT_IMPLEMENTED;
#endif
}

NTSTATUS cli_get_session_key(TALLOC_CTX *mem_ctx,
			     struct rpc_pipe_client *cli,
			     DATA_BLOB *session_key)
{
	if (!session_key || !cli) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (!cli->auth) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	switch (cli->auth->auth_type) {
		case PIPE_AUTH_TYPE_SCHANNEL:
			*session_key = data_blob_talloc(mem_ctx,
				cli->auth->a_u.schannel_auth->sess_key, 16);
			break;
		case PIPE_AUTH_TYPE_NTLMSSP:
		case PIPE_AUTH_TYPE_SPNEGO_NTLMSSP:
			*session_key = data_blob_talloc(mem_ctx,
				cli->auth->a_u.ntlmssp_state->session_key.data,
				cli->auth->a_u.ntlmssp_state->session_key.length);
			break;
		case PIPE_AUTH_TYPE_KRB5:
		case PIPE_AUTH_TYPE_SPNEGO_KRB5:
			*session_key = data_blob_talloc(mem_ctx,
				cli->auth->a_u.kerberos_auth->session_key.data,
				cli->auth->a_u.kerberos_auth->session_key.length);
			break;
		case PIPE_AUTH_TYPE_NONE:
		default:
			return NT_STATUS_NO_USER_SESSION_KEY;
	}

	return NT_STATUS_OK;
}
