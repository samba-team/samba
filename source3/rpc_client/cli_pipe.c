/* 
 *  Unix SMB/CIFS implementation.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-1998,
 *  Copyright (C) Luke Kenneth Casson Leighton 1996-1998,
 *  Copyright (C) Paul Ashton                       1998.
 *  Copyright (C) Jeremy Allison                    1999.
 *  Copyright (C) Andrew Bartlett                   2003.
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

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_RPC_CLI

extern struct pipe_id_info pipe_names[];

/* convert pipe auth flags into the RPC auth type and level */

void get_auth_type_level(int pipe_auth_flags, int *auth_type, int *auth_level) 
{
	*auth_type = 0;
	*auth_level = 0;
	if (pipe_auth_flags & AUTH_PIPE_SEAL) {
		*auth_level = RPC_PIPE_AUTH_SEAL_LEVEL;
	} else if (pipe_auth_flags & AUTH_PIPE_SIGN) {
		*auth_level = RPC_PIPE_AUTH_SIGN_LEVEL;
	}
	
	if (pipe_auth_flags & AUTH_PIPE_NETSEC) {
		*auth_type = NETSEC_AUTH_TYPE;
	} else if (pipe_auth_flags & AUTH_PIPE_NTLMSSP) {
		*auth_type = NTLMSSP_AUTH_TYPE;
	}
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
 Use SMBreadX to get rest of one fragment's worth of rpc data.
 ********************************************************************/

static BOOL rpc_read(struct cli_state *cli, prs_struct *rdata, uint32 data_to_read, uint32 *rdata_offset)
{
	size_t size = (size_t)cli->max_recv_frag;
	int stream_offset = 0;
	int num_read;
	char *pdata;
	int extra_data_size = ((int)*rdata_offset) + ((int)data_to_read) - (int)prs_data_size(rdata);

	DEBUG(5,("rpc_read: data_to_read: %u rdata offset: %u extra_data_size: %d\n",
		(int)data_to_read, (unsigned int)*rdata_offset, extra_data_size));

	/*
	 * Grow the buffer if needed to accommodate the data to be read.
	 */

	if (extra_data_size > 0) {
		if(!prs_force_grow(rdata, (uint32)extra_data_size)) {
			DEBUG(0,("rpc_read: Failed to grow parse struct by %d bytes.\n", extra_data_size ));
			return False;
		}
		DEBUG(5,("rpc_read: grew buffer by %d bytes to %u\n", extra_data_size, prs_data_size(rdata) ));
	}

	pdata = prs_data_p(rdata) + *rdata_offset;

	do /* read data using SMBreadX */
	{
		uint32 ecode;
		uint8 eclass;

		if (size > (size_t)data_to_read)
			size = (size_t)data_to_read;

		num_read = (int)cli_read(cli, cli->nt_pipe_fnum, pdata, (off_t)stream_offset, size);

		DEBUG(5,("rpc_read: num_read = %d, read offset: %d, to read: %d\n",
		          num_read, stream_offset, data_to_read));

		if (cli_is_dos_error(cli)) {
                        cli_dos_error(cli, &eclass, &ecode);
                        if (eclass != ERRDOS && ecode != ERRmoredata) {
                                DEBUG(0,("rpc_read: Error %d/%u in cli_read\n",
                                         eclass, (unsigned int)ecode));
                                return False;
                        }
		}

		data_to_read -= num_read;
		stream_offset += num_read;
		pdata += num_read;

	} while (num_read > 0 && data_to_read > 0);
	/* && err == (0x80000000 | STATUS_BUFFER_OVERFLOW)); */

	/*
	 * Update the current offset into rdata by the amount read.
	 */
	*rdata_offset += stream_offset;

	return True;
}

/****************************************************************************
 Checks the header. This will set the endian bit in the rdata prs_struct. JRA.
 ****************************************************************************/

static BOOL rpc_check_hdr(prs_struct *rdata, RPC_HDR *rhdr, 
                          BOOL *first, BOOL *last, uint32 *len)
{
	DEBUG(5,("rpc_check_hdr: rdata->data_size = %u\n", (uint32)prs_data_size(rdata) ));

	/* Next call sets endian bit. */

	if(!smb_io_rpc_hdr("rpc_hdr   ", rhdr, rdata, 0)) {
		DEBUG(0,("rpc_check_hdr: Failed to unmarshall RPC_HDR.\n"));
		return False;
	}

	if (prs_offset(rdata) != RPC_HEADER_LEN) {
		DEBUG(0,("rpc_check_hdr: offset was %x, should be %x.\n", prs_offset(rdata), RPC_HEADER_LEN));
		return False;
	}

	(*first) = ((rhdr->flags & RPC_FLG_FIRST) != 0);
	(*last) = ((rhdr->flags & RPC_FLG_LAST ) != 0);
	(*len) = (uint32)rhdr->frag_len - prs_data_size(rdata);

	return (rhdr->pkt_type != RPC_FAULT);
}

/****************************************************************************
 Verify data on an rpc pipe.
 The VERIFY & SEAL code is only executed on packets that look like this :

 Request/Response PDU's look like the following...

 |<------------------PDU len----------------------------------------------->|
 |<-HDR_LEN-->|<--REQ LEN------>|.............|<-AUTH_HDRLEN->|<-AUTH_LEN-->|

 +------------+-----------------+-------------+---------------+-------------+
 | RPC HEADER | REQ/RESP HEADER | DATA ...... | AUTH_HDR      | AUTH DATA   |
 +------------+-----------------+-------------+---------------+-------------+

 Never on bind requests/responses.
 ****************************************************************************/

static BOOL rpc_auth_pipe(struct cli_state *cli, prs_struct *rdata,
			  uint32 fragment_start, int len, int auth_len, uint8 pkt_type,
			  int *pauth_padding_len)
{
	
	/*
	 * The following is that length of the data we must sign or seal.
	 * This doesn't include the RPC headers or the auth_len or the RPC_HDR_AUTH_LEN
	 * preceeding the auth_data.
	 */

	int data_len = len - RPC_HEADER_LEN - RPC_HDR_RESP_LEN - RPC_HDR_AUTH_LEN - auth_len;

	/*
	 * The start of the data to sign/seal is just after the RPC headers.
	 */
	char *reply_data = prs_data_p(rdata) + fragment_start + RPC_HEADER_LEN + RPC_HDR_REQ_LEN;

	RPC_HDR_AUTH rhdr_auth; 

	char *dp = prs_data_p(rdata) + fragment_start + len -
		RPC_HDR_AUTH_LEN - auth_len;
	prs_struct auth_verf;

	*pauth_padding_len = 0;

	if (auth_len == 0) {
		if (cli->pipe_auth_flags == 0) {
			/* move along, nothing to see here */
			return True;
		}

		DEBUG(2, ("No authenticaton header recienved on reply, but this pipe is authenticated\n"));
		return False;
	}

	DEBUG(5,("rpc_auth_pipe: pkt_type: %d len: %d auth_len: %d NTLMSSP %s schannel %s sign %s seal %s \n",
		 pkt_type, len, auth_len, 
		 BOOLSTR(cli->pipe_auth_flags & AUTH_PIPE_NTLMSSP), 
		 BOOLSTR(cli->pipe_auth_flags & AUTH_PIPE_NETSEC), 
		 BOOLSTR(cli->pipe_auth_flags & AUTH_PIPE_SIGN), 
		 BOOLSTR(cli->pipe_auth_flags & AUTH_PIPE_SEAL)));

	if (dp - prs_data_p(rdata) > prs_data_size(rdata)) {
		DEBUG(0,("rpc_auth_pipe: schannel auth data > data size !\n"));
		return False;
	}

	DEBUG(10,("rpc_auth_pipe: packet:\n"));
	dump_data(100, dp, auth_len);

	prs_init(&auth_verf, 0, cli->mem_ctx, UNMARSHALL);
	
	/* The endinness must be preserved. JRA. */
	prs_set_endian_data( &auth_verf, rdata->bigendian_data);
	
	/* Point this new parse struct at the auth section of the main 
	   parse struct - rather than copying it.  Avoids needing to
	   free it on every error
	*/
	prs_give_memory(&auth_verf, dp, RPC_HDR_AUTH_LEN + auth_len, False /* not dynamic */);
	prs_set_offset(&auth_verf, 0);

	{
		int auth_type;
		int auth_level;
		if (!smb_io_rpc_hdr_auth("auth_hdr", &rhdr_auth, &auth_verf, 0)) {
			DEBUG(0, ("rpc_auth_pipe: Could not parse auth header\n"));
			return False;
		}

		/* Let the caller know how much padding at the end of the data */
		*pauth_padding_len = rhdr_auth.padding;
		
		/* Check it's the type of reply we were expecting to decode */

		get_auth_type_level(cli->pipe_auth_flags, &auth_type, &auth_level);
		if (rhdr_auth.auth_type != auth_type) {
			DEBUG(0, ("BAD auth type %d (should be %d)\n",
				  rhdr_auth.auth_type, auth_type));
			return False;
		}
		
		if (rhdr_auth.auth_level != auth_level) {
			DEBUG(0, ("BAD auth level %d (should be %d)\n", 
				  rhdr_auth.auth_level, auth_level));
			return False;
		}
	}

	if (pkt_type == RPC_BINDACK) {
		if (cli->pipe_auth_flags & AUTH_PIPE_NTLMSSP) {
			/* copy the next auth_len bytes into a buffer for 
			   later use */

			DATA_BLOB ntlmssp_verf = data_blob(NULL, auth_len);
			BOOL store_ok;

			/* save the reply away, for use a little later */
			prs_copy_data_out((char *)ntlmssp_verf.data, &auth_verf, auth_len);

			store_ok = (NT_STATUS_IS_OK(ntlmssp_store_response(cli->ntlmssp_pipe_state, 
									   ntlmssp_verf)));

			data_blob_free(&ntlmssp_verf);
			return store_ok;
		} 
		else if (cli->pipe_auth_flags & AUTH_PIPE_NETSEC) {
			/* nothing to do here - we don't seem to be able to 
			   validate the bindack based on VL's comments */
			return True;
		}
	}
	
	if (cli->pipe_auth_flags & AUTH_PIPE_NTLMSSP) {
		NTSTATUS nt_status;
		DATA_BLOB sig;
		if ((cli->pipe_auth_flags & AUTH_PIPE_SIGN) ||
		    (cli->pipe_auth_flags & AUTH_PIPE_SEAL)) {
			if (auth_len != RPC_AUTH_NTLMSSP_CHK_LEN) {
				DEBUG(0,("rpc_auth_pipe: wrong ntlmssp auth len %d\n", auth_len));
				return False;
			}
			sig = data_blob(NULL, auth_len);
			prs_copy_data_out((char *)sig.data, &auth_verf, auth_len);
		}
	
		/*
		 * Unseal any sealed data in the PDU, not including the
		 * 8 byte auth_header or the auth_data.
		 */

		/*
		 * Now unseal and check the auth verifier in the auth_data at
		 * the end of the packet. 
		 */

		if (cli->pipe_auth_flags & AUTH_PIPE_SEAL) {
			if (data_len < 0) {
				DEBUG(1, ("Can't unseal - data_len < 0!!\n"));
				return False;
			}
			nt_status = ntlmssp_unseal_packet(cli->ntlmssp_pipe_state, 
								 (unsigned char *)reply_data, data_len,
								 &sig);
		} 
		else if (cli->pipe_auth_flags & AUTH_PIPE_SIGN) {
			nt_status = ntlmssp_check_packet(cli->ntlmssp_pipe_state, 
								(const unsigned char *)reply_data, data_len,
								&sig);
		}

		data_blob_free(&sig);

		if (!NT_STATUS_IS_OK(nt_status)) {
			DEBUG(0, ("rpc_auth_pipe: could not validate "
				  "incoming NTLMSSP packet!\n"));
			return False;
		}
	}

	if (cli->pipe_auth_flags & AUTH_PIPE_NETSEC) {
		RPC_AUTH_NETSEC_CHK chk;

		if (auth_len != RPC_AUTH_NETSEC_CHK_LEN) {
			DEBUG(0,("rpc_auth_pipe: wrong schannel auth len %d\n", auth_len));
			return False;
		}

		if (!smb_io_rpc_auth_netsec_chk("schannel_auth_sign", 
						&chk, &auth_verf, 0)) {
			DEBUG(0, ("rpc_auth_pipe: schannel unmarshalling "
				  "RPC_AUTH_NETSECK_CHK failed\n"));
			return False;
		}

		if (!netsec_decode(&cli->auth_info,
				   cli->pipe_auth_flags,
				   SENDER_IS_ACCEPTOR,
				   &chk, reply_data, data_len)) {
			DEBUG(0, ("rpc_auth_pipe: Could not decode schannel\n"));
			return False;
		}

		cli->auth_info.seq_num++;

	}
	return True;
}


/****************************************************************************
 Send data on an rpc pipe via trans, which *must* be the last fragment.
 receive response data from an rpc pipe, which may be large...

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

 Where the presence of the AUTH_HDR and AUTH are dependent on the
 signing & sealing being negotiated.

 ****************************************************************************/

static BOOL rpc_api_pipe(struct cli_state *cli, prs_struct *data, prs_struct *rdata,
			 uint8 expected_pkt_type)
{
	uint32 len;
	char *rparam = NULL;
	uint32 rparam_len = 0;
	uint16 setup[2];
	BOOL first = True;
	BOOL last  = True;
	RPC_HDR rhdr;
	char *pdata = data ? prs_data_p(data) : NULL;
	uint32 data_len = data ? prs_offset(data) : 0;
	char *prdata = NULL;
	uint32 rdata_len = 0;
	uint32 current_offset = 0;
	uint32 fragment_start = 0;
	uint32 max_data = cli->max_xmit_frag ? cli->max_xmit_frag : 1024;
	int auth_padding_len = 0;

	/* Create setup parameters - must be in native byte order. */

	setup[0] = TRANSACT_DCERPCCMD; 
	setup[1] = cli->nt_pipe_fnum; /* Pipe file handle. */

	DEBUG(5,("rpc_api_pipe: fnum:%x\n", (int)cli->nt_pipe_fnum));

	/* Send the RPC request and receive a response.  For short RPC
	   calls (about 1024 bytes or so) the RPC request and response
	   appears in a SMBtrans request and response.  Larger RPC
	   responses are received further on. */

	if (!cli_api_pipe(cli, "\\PIPE\\",
	          setup, 2, 0,                     /* Setup, length, max */
	          NULL, 0, 0,                      /* Params, length, max */
	          pdata, data_len, max_data,   	   /* data, length, max */
	          &rparam, &rparam_len,            /* return params, len */
	          &prdata, &rdata_len))            /* return data, len */
	{
		DEBUG(0, ("cli_pipe: return critical error. Error was %s\n", cli_errstr(cli)));
		return False;
	}

	/* Throw away returned params - we know we won't use them. */

	SAFE_FREE(rparam);

	if (prdata == NULL) {
		DEBUG(0,("rpc_api_pipe: pipe %x failed to return data.\n",
			(int)cli->nt_pipe_fnum));
		return False;
	}

	/*
	 * Give this memory as dynamically allocated to the return parse
	 * struct.  
	 */

	prs_give_memory(rdata, prdata, rdata_len, True);
	current_offset = rdata_len;

	/* This next call sets the endian bit correctly in rdata. */

	if (!rpc_check_hdr(rdata, &rhdr, &first, &last, &len)) {
		prs_mem_free(rdata);
		return False;
	}

	if (rhdr.pkt_type == RPC_BINDACK) {
		if (!last && !first) {
			DEBUG(5,("rpc_api_pipe: bug in server (AS/U?), setting fragment first/last ON.\n"));
			first = True;
			last = True;
		}
	}

	if (rhdr.pkt_type == RPC_BINDNACK) {
		DEBUG(3, ("Bind NACK received on pipe %x!\n", (int)cli->nt_pipe_fnum));
		prs_mem_free(rdata);
		return False;
	}

	if (rhdr.pkt_type == RPC_RESPONSE) {
		RPC_HDR_RESP rhdr_resp;
		if(!smb_io_rpc_hdr_resp("rpc_hdr_resp", &rhdr_resp, rdata, 0)) {
			DEBUG(5,("rpc_api_pipe: failed to unmarshal RPC_HDR_RESP.\n"));
			prs_mem_free(rdata);
			return False;
		}
	}

	if (rhdr.pkt_type != expected_pkt_type) {
		DEBUG(3, ("Connection to pipe %x got an unexpected RPC packet type - %d, not %d\n", (int)cli->nt_pipe_fnum, rhdr.pkt_type, expected_pkt_type));
		prs_mem_free(rdata);
		return False;
	}

	DEBUG(5,("rpc_api_pipe: len left: %u smbtrans read: %u\n",
	          (unsigned int)len, (unsigned int)rdata_len ));

	/* check if data to be sent back was too large for one SMBtrans */
	/* err status is only informational: the _real_ check is on the
           length */

	if (len > 0) { 
		/* || err == (0x80000000 | STATUS_BUFFER_OVERFLOW)) */

		/* Read the remaining part of the first response fragment */

		if (!rpc_read(cli, rdata, len, &current_offset)) {
			prs_mem_free(rdata);
			return False;
		}
	}

	/*
	 * Now we have a complete PDU, check the auth struct if any was sent.
	 */

	if(!rpc_auth_pipe(cli, rdata, fragment_start, rhdr.frag_len,
			  rhdr.auth_len, rhdr.pkt_type, &auth_padding_len)) {
		prs_mem_free(rdata);
		return False;
	}

	if (rhdr.auth_len != 0) {
		/*
		 * Drop the auth footers from the current offset.
		 * We need this if there are more fragments.
		 * The auth footers consist of the auth_data and the
		 * preceeding 8 byte auth_header.
		 */
		current_offset -= (auth_padding_len + RPC_HDR_AUTH_LEN + rhdr.auth_len);
	}
	
	/* 
	 * Only one rpc fragment, and it has been read.
	 */

	if (first && last) {
		DEBUG(6,("rpc_api_pipe: fragment first and last both set\n"));
		return True;
	}

	/*
	 * Read more fragments using SMBreadX until we get one with the
	 * last bit set.
	 */

	while (!last) {
		RPC_HDR_RESP rhdr_resp;
		int num_read;
		char hdr_data[RPC_HEADER_LEN+RPC_HDR_RESP_LEN];
		prs_struct hps;
		uint8 eclass;
		uint32 ecode;
		
		/*
		 * First read the header of the next PDU.
		 */

		prs_init(&hps, 0, cli->mem_ctx, UNMARSHALL);
		prs_give_memory(&hps, hdr_data, sizeof(hdr_data), False);

		num_read = cli_read(cli, cli->nt_pipe_fnum, hdr_data, 0, RPC_HEADER_LEN+RPC_HDR_RESP_LEN);
		if (cli_is_dos_error(cli)) {
                        cli_dos_error(cli, &eclass, &ecode);
                        if (eclass != ERRDOS && ecode != ERRmoredata) {
                                DEBUG(0,("rpc_api_pipe: cli_read error : %d/%d\n", eclass, ecode));
                                return False;
                        }
		}

		DEBUG(5,("rpc_api_pipe: read header (size:%d)\n", num_read));

		if (num_read != RPC_HEADER_LEN+RPC_HDR_RESP_LEN) {
			DEBUG(0,("rpc_api_pipe: Error : requested %d bytes, got %d.\n",
				RPC_HEADER_LEN+RPC_HDR_RESP_LEN, num_read ));
			return False;
		}

		/* This call sets the endianness in hps. */

		if (!rpc_check_hdr(&hps, &rhdr, &first, &last, &len))
			return False;

		/* Ensure the endianness in rdata is set correctly - must be same as hps. */

		if (hps.bigendian_data != rdata->bigendian_data) {
			DEBUG(0,("rpc_api_pipe: Error : Endianness changed from %s to %s\n",
				rdata->bigendian_data ? "big" : "little",
				hps.bigendian_data ? "big" : "little" ));
			return False;
		}

		if(!smb_io_rpc_hdr_resp("rpc_hdr_resp", &rhdr_resp, &hps, 0)) {
			DEBUG(0,("rpc_api_pipe: Error in unmarshalling RPC_HDR_RESP.\n"));
			return False;
		}

		if (first) {
			DEBUG(0,("rpc_api_pipe: secondary PDU rpc header has 'first' set !\n"));
			return False;
		}

		/*
		 * Now read the rest of the PDU.
		 */

		if (!rpc_read(cli, rdata, len, &current_offset)) {
			prs_mem_free(rdata);
			return False;
		}

		fragment_start = current_offset - len - RPC_HEADER_LEN - RPC_HDR_RESP_LEN;

		/*
		 * Verify any authentication footer.
		 */

		
		if(!rpc_auth_pipe(cli, rdata, fragment_start, rhdr.frag_len,
				  rhdr.auth_len, rhdr.pkt_type, &auth_padding_len)) {
			prs_mem_free(rdata);
			return False;
		}
		
		if (rhdr.auth_len != 0 ) {
			
			/*
			 * Drop the auth footers from the current offset.
			 * The auth footers consist of the auth_data and the
			 * preceeding 8 byte auth_header.
			 * We need this if there are more fragments.
			 */
			current_offset -= (auth_padding_len + RPC_HDR_AUTH_LEN + rhdr.auth_len);
		}
	}

	return True;
}

/*******************************************************************
 creates a DCE/RPC bind request

 - initialises the parse structure.
 - dynamically allocates the header data structure
 - caller is expected to free the header data structure once used.

 ********************************************************************/

static NTSTATUS create_rpc_bind_req(struct cli_state *cli, prs_struct *rpc_out, 
				    uint32 rpc_call_id,
				    RPC_IFACE *abstract, RPC_IFACE *transfer,
				    const char *my_name, const char *domain)
{
	RPC_HDR hdr;
	RPC_HDR_RB hdr_rb;
	RPC_HDR_AUTH hdr_auth;
	int auth_len = 0;
	int auth_type, auth_level;
	size_t saved_hdr_offset = 0;

	prs_struct auth_info;
	prs_init(&auth_info, RPC_HDR_AUTH_LEN, /* we will need at least this much */
		prs_get_mem_context(rpc_out), MARSHALL);

	if (cli->pipe_auth_flags) {
		get_auth_type_level(cli->pipe_auth_flags, &auth_type, &auth_level);
		
		/*
		 * Create the auth structs we will marshall.
		 */
		
		init_rpc_hdr_auth(&hdr_auth, auth_type, auth_level, 0x00, 1);
		
		/*
		 * Now marshall the data into the temporary parse_struct.
		 */
		
		if(!smb_io_rpc_hdr_auth("hdr_auth", &hdr_auth, &auth_info, 0)) {
			DEBUG(0,("create_rpc_bind_req: failed to marshall RPC_HDR_AUTH.\n"));
			prs_mem_free(&auth_info);
			return NT_STATUS_NO_MEMORY;
		}
		saved_hdr_offset = prs_offset(&auth_info);
	}
	
	if (cli->pipe_auth_flags & AUTH_PIPE_NTLMSSP) {

		NTSTATUS nt_status;
		DATA_BLOB null_blob = data_blob(NULL, 0);
		DATA_BLOB request;

		DEBUG(5, ("Processing NTLMSSP Negotiate\n"));
		nt_status = ntlmssp_update(cli->ntlmssp_pipe_state,
					   null_blob,
					   &request);

		if (!NT_STATUS_EQUAL(nt_status, 
				     NT_STATUS_MORE_PROCESSING_REQUIRED)) {
			prs_mem_free(&auth_info);
			return nt_status;
		}

		/* Auth len in the rpc header doesn't include auth_header. */
		auth_len = request.length;
		prs_copy_data_in(&auth_info, (char *)request.data, request.length);

		DEBUG(5, ("NTLMSSP Negotiate:\n"));
		dump_data(5, (const char *)request.data, request.length);

		data_blob_free(&request);

	} else if (cli->pipe_auth_flags & AUTH_PIPE_NETSEC) {
		RPC_AUTH_NETSEC_NEG netsec_neg;

		/* Use lp_workgroup() if domain not specified */

		if (!domain || !domain[0]) {
			DEBUG(10,("create_rpc_bind_req: no domain; assuming my own\n"));
			domain = lp_workgroup();
		}

		init_rpc_auth_netsec_neg(&netsec_neg, domain, my_name);

		/*
		 * Now marshall the data into the temporary parse_struct.
		 */

		if(!smb_io_rpc_auth_netsec_neg("netsec_neg",
					       &netsec_neg, &auth_info, 0)) {
			DEBUG(0,("Failed to marshall RPC_AUTH_NETSEC_NEG.\n"));
			prs_mem_free(&auth_info);
			return NT_STATUS_NO_MEMORY;
		}

		/* Auth len in the rpc header doesn't include auth_header. */
		auth_len = prs_offset(&auth_info) - saved_hdr_offset;
	}

	/* Create the request RPC_HDR */
	init_rpc_hdr(&hdr, RPC_BIND, 0x3, rpc_call_id, 
		RPC_HEADER_LEN + RPC_HDR_RB_LEN + prs_offset(&auth_info),
		auth_len);

	if(!smb_io_rpc_hdr("hdr"   , &hdr, rpc_out, 0)) {
		DEBUG(0,("create_rpc_bind_req: failed to marshall RPC_HDR.\n"));
		prs_mem_free(&auth_info);
		return NT_STATUS_NO_MEMORY;
	}

	/* create the bind request RPC_HDR_RB */
	init_rpc_hdr_rb(&hdr_rb, MAX_PDU_FRAG_LEN, MAX_PDU_FRAG_LEN, 0x0,
			0x1, 0x0, 0x1, abstract, transfer);

	/* Marshall the bind request data */
	if(!smb_io_rpc_hdr_rb("", &hdr_rb, rpc_out, 0)) {
		DEBUG(0,("create_rpc_bind_req: failed to marshall RPC_HDR_RB.\n"));
		prs_mem_free(&auth_info);
		return NT_STATUS_NO_MEMORY;
	}

	/*
	 * Grow the outgoing buffer to store any auth info.
	 */

	if(auth_len != 0) {
		if(!prs_append_prs_data( rpc_out, &auth_info)) {
			DEBUG(0,("create_rpc_bind_req: failed to grow parse struct to add auth.\n"));
			prs_mem_free(&auth_info);
			return NT_STATUS_NO_MEMORY;
		}
	}
	prs_mem_free(&auth_info);
	return NT_STATUS_OK;
}

/*******************************************************************
 Creates a DCE/RPC bind authentication response.
 This is the packet that is sent back to the server once we
 have received a BIND-ACK, to finish the third leg of
 the authentication handshake.
 ********************************************************************/

static NTSTATUS create_rpc_bind_resp(struct cli_state *cli,
				 uint32 rpc_call_id,
				 prs_struct *rpc_out)
{
	NTSTATUS nt_status;
	RPC_HDR hdr;
	RPC_HDR_AUTHA hdr_autha;
	DATA_BLOB ntlmssp_null_response = data_blob(NULL, 0);
	DATA_BLOB ntlmssp_reply;
	int auth_type, auth_level;

	/* The response is picked up from the internal cache,
	   where it was placed by the rpc_auth_pipe() code */
	nt_status = ntlmssp_update(cli->ntlmssp_pipe_state,
				   ntlmssp_null_response,
				   &ntlmssp_reply);
	
	if (!NT_STATUS_EQUAL(nt_status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		return nt_status;
	}

	/* Create the request RPC_HDR */
	init_rpc_hdr(&hdr, RPC_BINDRESP, 0x0, rpc_call_id,
		     RPC_HEADER_LEN + RPC_HDR_AUTHA_LEN + ntlmssp_reply.length,
		     ntlmssp_reply.length );
	
	/* Marshall it. */
	if(!smb_io_rpc_hdr("hdr", &hdr, rpc_out, 0)) {
		DEBUG(0,("create_rpc_bind_resp: failed to marshall RPC_HDR.\n"));
		data_blob_free(&ntlmssp_reply);
		return NT_STATUS_NO_MEMORY;
	}

	get_auth_type_level(cli->pipe_auth_flags, &auth_type, &auth_level);
	
	/* Create the request RPC_HDR_AUTHA */
	init_rpc_hdr_autha(&hdr_autha, MAX_PDU_FRAG_LEN, MAX_PDU_FRAG_LEN,
			   auth_type, auth_level, 0x00);

	if(!smb_io_rpc_hdr_autha("hdr_autha", &hdr_autha, rpc_out, 0)) {
		DEBUG(0,("create_rpc_bind_resp: failed to marshall RPC_HDR_AUTHA.\n"));
		data_blob_free(&ntlmssp_reply);
		return NT_STATUS_NO_MEMORY;
	}

	/*
	 * Append the auth data to the outgoing buffer.
	 */

	if(!prs_copy_data_in(rpc_out, (char *)ntlmssp_reply.data, ntlmssp_reply.length)) {
		DEBUG(0,("create_rpc_bind_req: failed to grow parse struct to add auth.\n"));
		data_blob_free(&ntlmssp_reply);
		return NT_STATUS_NO_MEMORY;
	}

	data_blob_free(&ntlmssp_reply);
	return NT_STATUS_OK;
}


/*******************************************************************
 Creates a DCE/RPC request.
 ********************************************************************/

static uint32 create_rpc_request(prs_struct *rpc_out, uint8 op_num, int data_len, int auth_len, uint8 flags, uint32 oldid, uint32 data_left)
{
	uint32 alloc_hint;
	RPC_HDR     hdr;
	RPC_HDR_REQ hdr_req;
	uint32 callid = oldid ? oldid : get_rpc_call_id();

	DEBUG(5,("create_rpc_request: opnum: 0x%x data_len: 0x%x\n", op_num, data_len));

	/* create the rpc header RPC_HDR */
	init_rpc_hdr(&hdr, RPC_REQUEST, flags,
	             callid, data_len, auth_len);

	/*
	 * The alloc hint should be the amount of data, not including 
	 * RPC headers & footers.
	 */

	if (auth_len != 0)
		alloc_hint = data_len - RPC_HEADER_LEN - RPC_HDR_AUTH_LEN - auth_len;
	else
		alloc_hint = data_len - RPC_HEADER_LEN;

	DEBUG(10,("create_rpc_request: data_len: %x auth_len: %x alloc_hint: %x\n",
	           data_len, auth_len, alloc_hint));

	/* Create the rpc request RPC_HDR_REQ */
	init_rpc_hdr_req(&hdr_req, alloc_hint, op_num);

	/* stream-time... */
	if(!smb_io_rpc_hdr("hdr    ", &hdr, rpc_out, 0))
		return 0;

	if(!smb_io_rpc_hdr_req("hdr_req", &hdr_req, rpc_out, 0))
		return 0;

	if (prs_offset(rpc_out) != RPC_HEADER_LEN + RPC_HDR_REQ_LEN)
		return 0;

	return callid;
}

/*******************************************************************
 Puts an auth header into an rpc request.
 ********************************************************************/

static BOOL create_auth_hdr(prs_struct *outgoing_packet, 
			    int auth_type, 
			    int auth_level, int padding)
{
	RPC_HDR_AUTH hdr_auth;

	init_rpc_hdr_auth(&hdr_auth, auth_type, auth_level,
			  padding, 1);
	if(!smb_io_rpc_hdr_auth("hdr_auth", &hdr_auth, 
				outgoing_packet, 0)) {
		DEBUG(0,("create_auth_hdr:Failed to marshal RPC_HDR_AUTH.\n"));
		return False;
	}
	return True;
}

/**
 * Send a request on an RPC pipe and get a response.
 *
 * @param data NDR contents of the request to be sent.
 * @param rdata Unparsed NDR response data.
**/

BOOL rpc_api_pipe_req(struct cli_state *cli, uint8 op_num,
                      prs_struct *data, prs_struct *rdata)
{
	uint32 auth_len, real_auth_len, auth_hdr_len, max_data, data_left, data_sent;
	NTSTATUS nt_status;
	BOOL ret = False;
	uint32 callid = 0;
	fstring dump_name;

	auth_len = 0;
	real_auth_len = 0;
	auth_hdr_len = 0;

	if (cli->pipe_auth_flags & AUTH_PIPE_SIGN) {	
		if (cli->pipe_auth_flags & AUTH_PIPE_NTLMSSP) {	
			auth_len = RPC_AUTH_NTLMSSP_CHK_LEN;
		}
		if (cli->pipe_auth_flags & AUTH_PIPE_NETSEC) {	
			auth_len = RPC_AUTH_NETSEC_CHK_LEN;
		}
		auth_hdr_len = RPC_HDR_AUTH_LEN;
	}

	/*
	 * calc how much actual data we can send in a PDU fragment
	 */
	max_data = cli->max_xmit_frag - RPC_HEADER_LEN - RPC_HDR_REQ_LEN -
		auth_hdr_len - auth_len - 8;
	
	for (data_left = prs_offset(data), data_sent = 0; data_left > 0;) {
		prs_struct outgoing_packet;
		prs_struct sec_blob;
		uint32 data_len, send_size;
		uint8 flags = 0;
		uint32 auth_padding = 0;
		DATA_BLOB sign_blob;

		/*
		 * how much will we send this time
		 */
		send_size = MIN(data_left, max_data);

		if (!prs_init(&sec_blob, send_size, /* will need at least this much */
			      cli->mem_ctx, MARSHALL)) {
			DEBUG(0,("Could not malloc %u bytes",
				 send_size+auth_padding));
			return False;
		}

		if(!prs_append_some_prs_data(&sec_blob, data, 
					     data_sent, send_size)) {
			DEBUG(0,("Failed to append data to netsec blob\n"));
			prs_mem_free(&sec_blob);
			return False;
		}

		/*
		 * NT expects the data that is sealed to be 8-byte
		 * aligned. The padding must be encrypted as well and
		 * taken into account when generating the
		 * authentication verifier. The amount of padding must
		 * be stored in the auth header.
		 */

		if (cli->pipe_auth_flags) {
			size_t data_and_padding_size;
			int auth_type;
			int auth_level;
			prs_align_uint64(&sec_blob);

			get_auth_type_level(cli->pipe_auth_flags, &auth_type, &auth_level);

			data_and_padding_size = prs_offset(&sec_blob);
			auth_padding = data_and_padding_size - send_size;

			/* insert the auth header */
			
			if(!create_auth_hdr(&sec_blob, auth_type, auth_level, auth_padding)) {
				prs_mem_free(&sec_blob);
				return False;
			}
			
			/* create an NTLMSSP signature */
			if (cli->pipe_auth_flags & AUTH_PIPE_NTLMSSP) {
				/*
				 * Seal the outgoing data if requested.
				 */
				if (cli->pipe_auth_flags & AUTH_PIPE_SEAL) {
					
					nt_status = ntlmssp_seal_packet(cli->ntlmssp_pipe_state,
									       (unsigned char*)prs_data_p(&sec_blob),
									       data_and_padding_size,
									       &sign_blob);
					if (!NT_STATUS_IS_OK(nt_status)) {
						prs_mem_free(&sec_blob);
						return False;
					}
				} 
				else if (cli->pipe_auth_flags & AUTH_PIPE_SIGN) {
					
					nt_status = ntlmssp_sign_packet(cli->ntlmssp_pipe_state,
									       (unsigned char*)prs_data_p(&sec_blob),
									       data_and_padding_size, &sign_blob);
					if (!NT_STATUS_IS_OK(nt_status)) {
						prs_mem_free(&sec_blob);
						return False;
					}
				}
				

				/* write auth footer onto the packet */
				real_auth_len = sign_blob.length;
				
				prs_copy_data_in(&sec_blob, (char *)sign_blob.data, sign_blob.length);
				data_blob_free(&sign_blob);

			}
			else if (cli->pipe_auth_flags & AUTH_PIPE_NETSEC) {	
				size_t parse_offset_marker;
				RPC_AUTH_NETSEC_CHK verf;
				DEBUG(10,("SCHANNEL seq_num=%d\n", cli->auth_info.seq_num));
				
				netsec_encode(&cli->auth_info, 
					      cli->pipe_auth_flags,
					      SENDER_IS_INITIATOR,
					      &verf,
					      prs_data_p(&sec_blob),
					      data_and_padding_size);

				cli->auth_info.seq_num++;

				/* write auth footer onto the packet */
				
				parse_offset_marker = prs_offset(&sec_blob);
				if (!smb_io_rpc_auth_netsec_chk("", &verf,
								&sec_blob, 0)) {
					prs_mem_free(&sec_blob);
					return False;
				}
				real_auth_len = prs_offset(&sec_blob) - parse_offset_marker;
			}
		}

		data_len = RPC_HEADER_LEN + RPC_HDR_REQ_LEN + prs_offset(&sec_blob);

		/*
		 * Malloc parse struct to hold it (and enough for alignments).
		 */
		if(!prs_init(&outgoing_packet, data_len + 8, 
			     cli->mem_ctx, MARSHALL)) {
			DEBUG(0,("rpc_api_pipe_req: Failed to malloc %u bytes.\n", (unsigned int)data_len ));
			return False;
		}

		if (data_left == prs_offset(data))
			flags |= RPC_FLG_FIRST;

		if (data_left <= max_data)
			flags |= RPC_FLG_LAST;
		/*
		 * Write out the RPC header and the request header.
		 */
		if(!(callid = create_rpc_request(&outgoing_packet, op_num, 
						 data_len, real_auth_len, flags, 
						 callid, data_left))) {
			DEBUG(0,("rpc_api_pipe_req: Failed to create RPC request.\n"));
			prs_mem_free(&outgoing_packet);
			prs_mem_free(&sec_blob);
			return False;
		}

		prs_append_prs_data(&outgoing_packet, &sec_blob);
		prs_mem_free(&sec_blob);

		DEBUG(100,("data_len: %x data_calc_len: %x\n", data_len, 
			   prs_offset(&outgoing_packet)));
		
		if (flags & RPC_FLG_LAST)
			ret = rpc_api_pipe(cli, &outgoing_packet, 
					   rdata, RPC_RESPONSE);
		else {
			cli_write(cli, cli->nt_pipe_fnum, 0x0008,
				   prs_data_p(&outgoing_packet),
				   data_sent, data_len);
		}
		prs_mem_free(&outgoing_packet);
		data_sent += send_size;
		data_left -= send_size;
	}
	/* Also capture received data */
	slprintf(dump_name, sizeof(dump_name) - 1, "reply_%s",
		 cli_pipe_get_name(cli));
	prs_dump(dump_name, op_num, rdata);

	return ret;
}

/****************************************************************************
 Set the handle state.
****************************************************************************/

static BOOL rpc_pipe_set_hnd_state(struct cli_state *cli, const char *pipe_name, uint16 device_state)
{
	BOOL state_set = False;
	char param[2];
	uint16 setup[2]; /* only need 2 uint16 setup parameters */
	char *rparam = NULL;
	char *rdata = NULL;
	uint32 rparam_len, rdata_len;

	if (pipe_name == NULL)
		return False;

	DEBUG(5,("Set Handle state Pipe[%x]: %s - device state:%x\n",
	cli->nt_pipe_fnum, pipe_name, device_state));

	/* create parameters: device state */
	SSVAL(param, 0, device_state);

	/* create setup parameters. */
	setup[0] = 0x0001; 
	setup[1] = cli->nt_pipe_fnum; /* pipe file handle.  got this from an SMBOpenX. */

	/* send the data on \PIPE\ */
	if (cli_api_pipe(cli, "\\PIPE\\",
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

/****************************************************************************
 check the rpc bind acknowledge response
****************************************************************************/

int get_pipe_index( const char *pipe_name )
{
	int pipe_idx = 0;

	while (pipe_names[pipe_idx].client_pipe != NULL) {
		if (strequal(pipe_name, pipe_names[pipe_idx].client_pipe )) 
			return pipe_idx;
		pipe_idx++;
	};

	return -1;
}


/****************************************************************************
 check the rpc bind acknowledge response
****************************************************************************/

const char* get_pipe_name_from_index( const int pipe_index )
{

	if ( (pipe_index < 0) || (pipe_index >= PI_MAX_PIPES) )
		return NULL;

	return pipe_names[pipe_index].client_pipe;		
}

/****************************************************************************
 Check to see if this pipe index points to one of 
 the pipes only supported by Win2k
 ****************************************************************************/

BOOL is_win2k_pipe( const int pipe_idx )
{
	switch ( pipe_idx )
	{
		case PI_LSARPC_DS:
			return True;
	}
	
	return False;
}

/****************************************************************************
 check the rpc bind acknowledge response
****************************************************************************/

static BOOL valid_pipe_name(const int pipe_idx, RPC_IFACE *abstract, RPC_IFACE *transfer)
{
	if ( pipe_idx >= PI_MAX_PIPES ) {
		DEBUG(0,("valid_pipe_name: Programmer error!  Invalid pipe index [%d]\n",
			pipe_idx));
		return False;
	}

	DEBUG(5,("Bind Abstract Syntax: "));	
	dump_data(5, (char*)&(pipe_names[pipe_idx].abstr_syntax), 
	          sizeof(pipe_names[pipe_idx].abstr_syntax));
	DEBUG(5,("Bind Transfer Syntax: "));
	dump_data(5, (char*)&(pipe_names[pipe_idx].trans_syntax),
	          sizeof(pipe_names[pipe_idx].trans_syntax));

	/* copy the required syntaxes out so we can do the right bind */
	
	*transfer = pipe_names[pipe_idx].trans_syntax;
	*abstract = pipe_names[pipe_idx].abstr_syntax;

	return True;
}

/****************************************************************************
 check the rpc bind acknowledge response
****************************************************************************/

static BOOL check_bind_response(RPC_HDR_BA *hdr_ba, const int pipe_idx, RPC_IFACE *transfer)
{
# if 0	/* JERRY -- apparently ASU forgets to fill in the server pipe name sometimes */
	if ( hdr_ba->addr.len <= 0)
		return False;
		
	if ( !strequal(hdr_ba->addr.str, pipe_names[pipe_idx].client_pipe) &&
	     !strequal(hdr_ba->addr.str, pipe_names[pipe_idx].server_pipe) )
	{
		DEBUG(4,("bind_rpc_pipe: pipe_name %s != expected pipe %s.  oh well!\n",
		         pipe_names[i].server_pipe ,hdr_ba->addr.str));
		return False;
	}
	
	DEBUG(5,("bind_rpc_pipe: server pipe_name found: %s\n", pipe_names[i].server_pipe ));

	if (pipe_names[pipe_idx].server_pipe == NULL) {
		DEBUG(2,("bind_rpc_pipe: pipe name %s unsupported\n", hdr_ba->addr.str));
		return False;
	}
#endif 	/* JERRY */

	/* check the transfer syntax */
	if ((hdr_ba->transfer.version != transfer->version) ||
	     (memcmp(&hdr_ba->transfer.uuid, &transfer->uuid, sizeof(transfer->uuid)) !=0)) {
		DEBUG(2,("bind_rpc_pipe: transfer syntax differs\n"));
		return False;
	}

	/* lkclXXXX only accept one result: check the result(s) */
	if (hdr_ba->res.num_results != 0x1 || hdr_ba->res.result != 0) {
		DEBUG(2,("bind_rpc_pipe: bind denied results: %d reason: %x\n",
		          hdr_ba->res.num_results, hdr_ba->res.reason));
	}

	DEBUG(5,("bind_rpc_pipe: accepted!\n"));
	return True;
}

/****************************************************************************
 Create and send the third packet in an RPC auth.
****************************************************************************/

static BOOL rpc_send_auth_reply(struct cli_state *cli, prs_struct *rdata, uint32 rpc_call_id)
{
	prs_struct rpc_out;
	ssize_t ret;

	prs_init(&rpc_out, RPC_HEADER_LEN + RPC_HDR_AUTHA_LEN, /* need at least this much */ 
		 cli->mem_ctx, MARSHALL);

	if (!NT_STATUS_IS_OK(create_rpc_bind_resp(cli, rpc_call_id,
						  &rpc_out))) {
		return False;
	}

	if ((ret = cli_write(cli, cli->nt_pipe_fnum, 0x8, prs_data_p(&rpc_out), 
			0, (size_t)prs_offset(&rpc_out))) != (ssize_t)prs_offset(&rpc_out)) {
		DEBUG(0,("rpc_send_auth_reply: cli_write failed. Return was %d\n", (int)ret));
		prs_mem_free(&rpc_out);
		return False;
	}

	prs_mem_free(&rpc_out);
	return True;
}

/****************************************************************************
 Do an rpc bind.
****************************************************************************/

static BOOL rpc_pipe_bind(struct cli_state *cli, int pipe_idx, const char *my_name)
{
	RPC_IFACE abstract;
	RPC_IFACE transfer;
	prs_struct rpc_out;
	prs_struct rdata;
	uint32 rpc_call_id;
	char buffer[MAX_PDU_FRAG_LEN];

	if ( (pipe_idx < 0) || (pipe_idx >= PI_MAX_PIPES) )
		return False;

	DEBUG(5,("Bind RPC Pipe[%x]: %s\n", cli->nt_pipe_fnum, pipe_names[pipe_idx].client_pipe));

	if (!valid_pipe_name(pipe_idx, &abstract, &transfer))
		return False;

	prs_init(&rpc_out, 0, cli->mem_ctx, MARSHALL);

	/*
	 * Use the MAX_PDU_FRAG_LEN buffer to store the bind request.
	 */

	prs_give_memory( &rpc_out, buffer, sizeof(buffer), False);

	rpc_call_id = get_rpc_call_id();

	if (cli->pipe_auth_flags & AUTH_PIPE_NTLMSSP) {
		NTSTATUS nt_status;
		fstring password;

		DEBUG(5, ("NTLMSSP authenticated pipe selected\n"));

		nt_status = ntlmssp_client_start(&cli->ntlmssp_pipe_state);
		
		if (!NT_STATUS_IS_OK(nt_status))
			return False;

		/* Currently the NTLMSSP code does not implement NTLM2 correctly for signing or sealing */

		cli->ntlmssp_pipe_state->neg_flags &= ~NTLMSSP_NEGOTIATE_NTLM2;

		nt_status = ntlmssp_set_username(cli->ntlmssp_pipe_state, 
						 cli->user_name);
		if (!NT_STATUS_IS_OK(nt_status))
			return False;

		nt_status = ntlmssp_set_domain(cli->ntlmssp_pipe_state, 
					       cli->domain);	
		if (!NT_STATUS_IS_OK(nt_status))
			return False;

		if (cli->pwd.null_pwd) {
			nt_status = ntlmssp_set_password(cli->ntlmssp_pipe_state, 
							 NULL);
			if (!NT_STATUS_IS_OK(nt_status))
				return False;
		} else {
			pwd_get_cleartext(&cli->pwd, password);
			nt_status = ntlmssp_set_password(cli->ntlmssp_pipe_state, 
							 password);
			if (!NT_STATUS_IS_OK(nt_status))
				return False;
		}

		if (cli->pipe_auth_flags & AUTH_PIPE_SIGN) {
			cli->ntlmssp_pipe_state->neg_flags |= NTLMSSP_NEGOTIATE_SIGN;
		}

		if (cli->pipe_auth_flags & AUTH_PIPE_SEAL) {
			cli->ntlmssp_pipe_state->neg_flags |= NTLMSSP_NEGOTIATE_SEAL;
		}
	} else if (cli->pipe_auth_flags & AUTH_PIPE_NETSEC) {
		cli->auth_info.seq_num = 0;
	}

	/* Marshall the outgoing data. */
	create_rpc_bind_req(cli, &rpc_out, rpc_call_id,
	                    &abstract, &transfer,
	                    global_myname(), cli->domain);

	/* Initialize the incoming data struct. */
	prs_init(&rdata, 0, cli->mem_ctx, UNMARSHALL);

	/* send data on \PIPE\.  receive a response */
	if (rpc_api_pipe(cli, &rpc_out, &rdata, RPC_BINDACK)) {
		RPC_HDR_BA   hdr_ba;

		DEBUG(5, ("rpc_pipe_bind: rpc_api_pipe returned OK.\n"));

		if(!smb_io_rpc_hdr_ba("", &hdr_ba, &rdata, 0)) {
			DEBUG(0,("rpc_pipe_bind: Failed to unmarshall RPC_HDR_BA.\n"));
			prs_mem_free(&rdata);
			return False;
		}

		if(!check_bind_response(&hdr_ba, pipe_idx, &transfer)) {
			DEBUG(2,("rpc_pipe_bind: check_bind_response failed.\n"));
			prs_mem_free(&rdata);
			return False;
		}

		cli->max_xmit_frag = hdr_ba.bba.max_tsize;
		cli->max_recv_frag = hdr_ba.bba.max_rsize;

		/*
		 * If we're doing NTLMSSP auth we need to send a reply to
		 * the bind-ack to complete the 3-way challenge response
		 * handshake.
		 */

		if ((cli->pipe_auth_flags & AUTH_PIPE_NTLMSSP) 
		    && !rpc_send_auth_reply(cli, &rdata, rpc_call_id)) {
			DEBUG(0,("rpc_pipe_bind: rpc_send_auth_reply failed.\n"));
			prs_mem_free(&rdata);
			return False;
		}
		prs_mem_free(&rdata);
		return True;
	}

	return False;
}

/****************************************************************************
 Open a session.
 ****************************************************************************/

BOOL cli_nt_session_open(struct cli_state *cli, const int pipe_idx)
{
	int fnum;

	/* At the moment we can't have more than one pipe open over
           a cli connection. )-: */

	SMB_ASSERT(cli->nt_pipe_fnum == 0);
	
	/* The pipe index must fall within our array */

	SMB_ASSERT((pipe_idx >= 0) && (pipe_idx < PI_MAX_PIPES));

	if (cli->capabilities & CAP_NT_SMBS) {
		if ((fnum = cli_nt_create(cli, &pipe_names[pipe_idx].client_pipe[5], DESIRED_ACCESS_PIPE)) == -1) {
			DEBUG(0,("cli_nt_session_open: cli_nt_create failed on pipe %s to machine %s.  Error was %s\n",
				 &pipe_names[pipe_idx].client_pipe[5], cli->desthost, cli_errstr(cli)));
			return False;
		}

		cli->nt_pipe_fnum = (uint16)fnum;
	} else {
		if ((fnum = cli_open(cli, pipe_names[pipe_idx].client_pipe, O_CREAT|O_RDWR, DENY_NONE)) == -1) {
			DEBUG(1,("cli_nt_session_open: cli_open failed on pipe %s to machine %s.  Error was %s\n",
				 pipe_names[pipe_idx].client_pipe, cli->desthost, cli_errstr(cli)));
			return False;
		}

		cli->nt_pipe_fnum = (uint16)fnum;

		/**************** Set Named Pipe State ***************/
		if (!rpc_pipe_set_hnd_state(cli, pipe_names[pipe_idx].client_pipe, 0x4300)) {
			DEBUG(0,("cli_nt_session_open: pipe hnd state failed.  Error was %s\n",
				  cli_errstr(cli)));
			cli_close(cli, cli->nt_pipe_fnum);
			cli->nt_pipe_fnum = 0;
			return False;
		}
	}

	/******************* bind request on pipe *****************/

	if (!rpc_pipe_bind(cli, pipe_idx, global_myname())) {
		DEBUG(2,("cli_nt_session_open: rpc bind to %s failed\n",
			 get_pipe_name_from_index(pipe_idx)));
		cli_close(cli, cli->nt_pipe_fnum);
		cli->nt_pipe_fnum = 0;
		return False;
	}

	cli->pipe_idx = pipe_idx;

	/* 
	 * Setup the remote server name prefixed by \ and the machine account name.
	 */

	fstrcpy(cli->srv_name_slash, "\\\\");
	fstrcat(cli->srv_name_slash, cli->desthost);
	strupper_m(cli->srv_name_slash);

	fstrcpy(cli->clnt_name_slash, "\\\\");
	fstrcat(cli->clnt_name_slash, global_myname());
	strupper_m(cli->clnt_name_slash);

	fstrcpy(cli->mach_acct, global_myname());
	fstrcat(cli->mach_acct, "$");
	strupper_m(cli->mach_acct);

	/* Remember which pipe we're talking to */
	fstrcpy(cli->pipe_name, pipe_names[pipe_idx].client_pipe);

	return True;
}


/****************************************************************************
 Open a session to the NETLOGON pipe using schannel.

 (Assumes that the netlogon pipe is already open)
 ****************************************************************************/

NTSTATUS cli_nt_establish_netlogon(struct cli_state *cli, int sec_chan,
				   const uchar trust_password[16])
{
	NTSTATUS result;	
	uint32 neg_flags = NETLOGON_NEG_AUTH2_FLAGS;
	int fnum;

	cli_nt_netlogon_netsec_session_close(cli);

	if (lp_client_schannel() != False)
		neg_flags |= NETLOGON_NEG_SCHANNEL;

	result = cli_nt_setup_creds(cli, sec_chan, trust_password,
				    &neg_flags, 2);

	if (!NT_STATUS_IS_OK(result)) {
		cli_nt_session_close(cli);
		return result;
	}

	if ((lp_client_schannel() == True) &&
	    ((neg_flags & NETLOGON_NEG_SCHANNEL) == 0)) {

		DEBUG(3, ("Server did not offer schannel\n"));
		cli_nt_session_close(cli);
		return NT_STATUS_UNSUCCESSFUL;
	}

	if ((lp_client_schannel() == False) ||
	    ((neg_flags & NETLOGON_NEG_SCHANNEL) == 0)) {
		return NT_STATUS_OK;
		
		/* keep the existing connection to NETLOGON open */

	}

	/* Server offered schannel, so try it. */

	memcpy(cli->auth_info.sess_key, cli->sess_key,
	       sizeof(cli->auth_info.sess_key));

	cli->saved_netlogon_pipe_fnum = cli->nt_pipe_fnum;

	cli->pipe_auth_flags = AUTH_PIPE_NETSEC;
	cli->pipe_auth_flags |= AUTH_PIPE_SIGN;
	cli->pipe_auth_flags |= AUTH_PIPE_SEAL;

	if (cli->capabilities & CAP_NT_SMBS) {

		/* The secure channel connection must be opened on the same 
                   session (TCP connection) as the one the challenge was
                   requested from. */
		if ((fnum = cli_nt_create(cli, PIPE_NETLOGON_PLAIN,
					  DESIRED_ACCESS_PIPE)) == -1) {
			DEBUG(0,("cli_nt_create failed to %s machine %s. "
				 "Error was %s\n",
				 PIPE_NETLOGON, cli->desthost,
				 cli_errstr(cli)));
			return NT_STATUS_UNSUCCESSFUL;
		}
		
		cli->nt_pipe_fnum = (uint16)fnum;
	} else {
		if ((fnum = cli_open(cli, PIPE_NETLOGON,
				     O_CREAT|O_RDWR, DENY_NONE)) == -1) {
			DEBUG(0,("cli_open failed on pipe %s to machine %s. "
				 "Error was %s\n",
				 PIPE_NETLOGON, cli->desthost,
				 cli_errstr(cli)));
			return NT_STATUS_UNSUCCESSFUL;
		}

		cli->nt_pipe_fnum = (uint16)fnum;

		/**************** Set Named Pipe State ***************/
		if (!rpc_pipe_set_hnd_state(cli, PIPE_NETLOGON, 0x4300)) {
			DEBUG(0,("Pipe hnd state failed.  Error was %s\n",
				  cli_errstr(cli)));
			cli_close(cli, cli->nt_pipe_fnum);
			return NT_STATUS_UNSUCCESSFUL;
		}
	}
	
	if (!rpc_pipe_bind(cli, PI_NETLOGON, global_myname())) {
		DEBUG(2,("rpc bind to %s failed\n", PIPE_NETLOGON));
		cli_close(cli, cli->nt_pipe_fnum);
		return NT_STATUS_UNSUCCESSFUL;
	}

	return NT_STATUS_OK;
}


NTSTATUS cli_nt_setup_netsec(struct cli_state *cli, int sec_chan, int auth_flags,
			     const uchar trust_password[16])
{
	NTSTATUS result;	
	uint32 neg_flags = NETLOGON_NEG_AUTH2_FLAGS;
	cli->pipe_auth_flags = 0;

	if (lp_client_schannel() == False) {
		return NT_STATUS_OK;
	}

	if (!cli_nt_session_open(cli, PI_NETLOGON)) {
		DEBUG(0, ("Could not initialise %s\n",
			  get_pipe_name_from_index(PI_NETLOGON)));
		return NT_STATUS_UNSUCCESSFUL;
	}

	if (lp_client_schannel() != False)
		neg_flags |= NETLOGON_NEG_SCHANNEL;

	neg_flags |= NETLOGON_NEG_SCHANNEL;

	result = cli_nt_setup_creds(cli, sec_chan, trust_password,
				    &neg_flags, 2);

	if (!(neg_flags & NETLOGON_NEG_SCHANNEL) 
	    && lp_client_schannel() == True) {
		DEBUG(1, ("Could not negotiate SCHANNEL with the DC!\n"));
		result = NT_STATUS_UNSUCCESSFUL;
	}

	if (!NT_STATUS_IS_OK(result)) {
		ZERO_STRUCT(cli->auth_info.sess_key);
		ZERO_STRUCT(cli->sess_key);
		cli->pipe_auth_flags = 0;
		cli_nt_session_close(cli);
		return result;
	}

	memcpy(cli->auth_info.sess_key, cli->sess_key,
	       sizeof(cli->auth_info.sess_key));

	cli->saved_netlogon_pipe_fnum = cli->nt_pipe_fnum;
	cli->nt_pipe_fnum = 0;

	/* doing schannel, not per-user auth */
	cli->pipe_auth_flags = auth_flags;

	return NT_STATUS_OK;
}

const char *cli_pipe_get_name(struct cli_state *cli)
{
	return cli->pipe_name;
}


