
/* 
 *  Unix SMB/Netbios implementation.
 *  Version 1.9.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-1999,
 *  Copyright (C) Luke Kenneth Casson Leighton 1996-1999,
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


#ifdef SYSLOG
#undef SYSLOG
#endif

#include "includes.h"

extern int DEBUGLEVEL;
extern struct pipe_id_info pipe_names[];
extern pstring global_myname;

static void NTLMSSPcalc_ap( struct ntlmssp_auth_struct *a, unsigned char *data, int len)
{
	unsigned char *hash = a->ntlmssp_hash;
    unsigned char index_i = hash[256];
    unsigned char index_j = hash[257];
    int ind;

    for (ind = 0; ind < len; ind++)
    {
        unsigned char tc;
        unsigned char t;

        index_i++;
        index_j += hash[index_i];

        tc = hash[index_i];
        hash[index_i] = hash[index_j];
        hash[index_j] = tc;

        t = hash[index_i] + hash[index_j];
        data[ind] = data[ind] ^ hash[t];
    }

    hash[256] = index_i;
    hash[257] = index_j;
}

/****************************************************************************
 decrypt data on an rpc pipe
 ****************************************************************************/
static BOOL decode_ntlmssp_pdu(struct cli_connection *con,
				prs_struct *rdata,
				int len, int auth_len)
{
	RPC_AUTH_NTLMSSP_CHK chk;
	uint32 crc32;

	int data_len = len - 0x18 - auth_len - 8;
	char *reply_data = prs_data(rdata, 0x18);

	BOOL auth_verify;
	BOOL auth_seal  ;

	ntlmssp_auth_struct *a;
	a = (ntlmssp_auth_struct *)cli_conn_get_auth_info(con);

	if (a == NULL)
	{
		return False;
	}

	auth_verify = IS_BITS_SET_ALL(a->ntlmssp_chal.neg_flags,
	                              NTLMSSP_NEGOTIATE_SIGN);
	auth_seal   = IS_BITS_SET_ALL(a->ntlmssp_chal.neg_flags,
	                              NTLMSSP_NEGOTIATE_SEAL);

	DEBUG(5,("decode_ntlmssp_pdu: len: %d auth_len: %d verify %s seal %s\n",
	          len, auth_len, BOOLSTR(auth_verify), BOOLSTR(auth_seal)));

	if (reply_data == NULL) return False;

	if (auth_seal)
	{
		DEBUG(10,("decode_ntlmssp_pdu: seal\n"));
		dump_data(100, reply_data, data_len);
		NTLMSSPcalc_ap(a, (uchar*)reply_data, data_len);
		dump_data(100, reply_data, data_len);
	}

	if (auth_verify || auth_seal)
	{
		RPC_HDR_AUTH         rhdr_auth; 
		prs_struct auth_req;
		prs_init(&auth_req , 0x0, 4, True);
		prs_append_data(&auth_req,
		                prs_data(rdata, len - auth_len - 8),
		                8);
		smb_io_rpc_hdr_auth("hdr_auth", &rhdr_auth, &auth_req, 0);
		prs_free_data(&auth_req);

		if (!rpc_hdr_ntlmssp_auth_chk(&rhdr_auth))
		{
			return False;
		}
	}

	if (auth_verify)
	{
		prs_struct auth_verf;
		char *data = prs_data(rdata, len - auth_len);
		if (data == NULL) return False;

		DEBUG(10,("decode_ntlmssp_pdu: verify\n"));
		dump_data(100, data, auth_len);
		NTLMSSPcalc_ap(a, (uchar*)(data+4), auth_len - 4);
		prs_init(&auth_verf, 0x0, 4, True);
		prs_append_data(&auth_verf, data, 16);
		smb_io_rpc_auth_ntlmssp_chk("auth_sign", &chk, &auth_verf, 0);
		dump_data(100, data, auth_len);
		prs_free_data(&auth_verf);
	}

	if (auth_verify)
	{
		crc32 = crc32_calc_buffer(data_len, prs_data(rdata, 0x18));
		if (!rpc_auth_ntlmssp_chk(&chk, crc32 , a->ntlmssp_seq_num))
		{
			return False;
		}
		a->ntlmssp_seq_num++;
	}
	return True;
}

/****************************************************************************
 send a request on an rpc pipe.
 ****************************************************************************/
static BOOL create_ntlmssp_pdu(struct cli_connection *con,
				uint8 op_num,
				prs_struct *data, int data_start, int *data_end,
				prs_struct *dataa,
				uint8 *flags)
{
	prs_struct data_t;
	prs_struct hdr;
	prs_struct hdr_auth;
	prs_struct auth_verf;
	int data_len;
	int frag_len;
	int auth_len;
	BOOL auth_verify;
	BOOL auth_seal;
	uint32 crc32 = 0;

	struct ntdom_info *nt = cli_conn_get_ntinfo(con);
	ntlmssp_auth_struct *a;
	a = (ntlmssp_auth_struct *)cli_conn_get_auth_info(con);

	if (a == NULL)
	{
		return False;
	}

	*flags = 0;

	auth_verify = IS_BITS_SET_ALL(a->ntlmssp_chal.neg_flags,
	                              NTLMSSP_NEGOTIATE_SIGN);
	auth_seal   = IS_BITS_SET_ALL(a->ntlmssp_chal.neg_flags,
	                              NTLMSSP_NEGOTIATE_SEAL);

	auth_len = (auth_verify ? 16 : 0);
	data_len = data->offset - data_start;

	if (data_start == 0)
	{
		(*flags) |= RPC_FLG_FIRST;
	}

	if (data_len > nt->max_recv_frag)
	{
		data_len = nt->max_recv_frag - (auth_len + (auth_verify ? 8 : 0) + 0x18);
	}
	else
	{
		(*flags) |= RPC_FLG_LAST;
	}

	(*data_end) += data_len;

	/* happen to know that NTLMSSP authentication verifier is 16 bytes */
	frag_len = data_len + auth_len + (auth_verify ? 8 : 0) + 0x18;

	prs_init(&data_t   , 0       , 4, False);
	prs_init(&hdr      , frag_len, 4, False);
	prs_init(&hdr_auth , 8       , 4, False);
	prs_init(&auth_verf, auth_len, 4, False);

	prs_append_data(&data_t, prs_data(data, data_start), data_len);
	data_t.end = data_t.data_size;
	data_t.offset = data_t.data_size;

	create_rpc_request(&hdr, op_num, (*flags), frag_len, auth_len);

	if (auth_seal)
	{
		char *buf = prs_data(&data_t, 0);
		size_t len = prs_buf_len(&data_t);
		crc32 = crc32_calc_buffer(len, buf);
		NTLMSSPcalc_ap(a, (uchar*)buf, len);
	}

	if (auth_seal || auth_verify)
	{
		RPC_HDR_AUTH         rhdr_auth;

		make_rpc_hdr_auth(&rhdr_auth, 0x0a, 0x06, 0x08, (auth_verify ? 1 : 0));
		smb_io_rpc_hdr_auth("hdr_auth", &rhdr_auth, &hdr_auth, 0);
	}

	if (auth_verify)
	{
		RPC_AUTH_NTLMSSP_CHK chk;

		make_rpc_auth_ntlmssp_chk(&chk, NTLMSSP_SIGN_VERSION, crc32, a->ntlmssp_seq_num++);
		smb_io_rpc_auth_ntlmssp_chk("auth_sign", &chk, &auth_verf, 0);
		NTLMSSPcalc_ap(a, (uchar*)prs_data(&auth_verf, 4), 12);
	}

	if (auth_seal || auth_verify)
	{
		prs_link(NULL     , &hdr      , &data_t   );
		prs_link(&hdr     , &data_t   , &hdr_auth );
		prs_link(&data_t  , &hdr_auth , &auth_verf);
		prs_link(&hdr_auth, &auth_verf, NULL      );
	}
	else
	{
		prs_link(NULL, &hdr   , &data_t);
		prs_link(&hdr, &data_t, NULL   );
	}

	DEBUG(100,("frag_len: 0x%x data_len: 0x%x data_calc_len: 0x%x\n",
		frag_len, data_len, prs_buf_len(&data_t)));

	if (frag_len != prs_buf_len(&hdr))
	{
		DEBUG(0,("expected fragment length does not match\n"));

		prs_free_data(&hdr_auth );
		prs_free_data(&auth_verf);
		prs_free_data(&hdr      );
		prs_free_data(&data_t   );

		return False;
	}

	DEBUG(100,("create_ntlmssp_pdu: %d\n", __LINE__));

	/* this is all a hack */
	prs_init(dataa, prs_buf_len(&hdr), 4, False);
	prs_debug_out(dataa, "create_ntlmssp_pdu", 200);
	prs_buf_copy(dataa->data, &hdr, 0, frag_len);

	DEBUG(100,("create_ntlmssp_pdu: %d\n", __LINE__));

	prs_free_data(&hdr_auth );
	prs_free_data(&auth_verf);
	prs_free_data(&hdr      );
	prs_free_data(&data_t   );

	return True;
}

/*******************************************************************
 creates a DCE/RPC bind request

 - initialises the parse structure.
 - dynamically allocates the header data structure
 - caller is expected to free the header data structure once used.

 ********************************************************************/
static BOOL create_ntlmssp_bind_req(struct cli_connection *con,
				prs_struct *data,
				uint32 rpc_call_id,
                                RPC_IFACE *abstract, RPC_IFACE *transfer)
{
	prs_struct rhdr;
	prs_struct rhdr_rb;
	prs_struct rhdr_auth;
	prs_struct auth_req;

	RPC_HDR_RB           hdr_rb;
	RPC_HDR              hdr;
	RPC_HDR_AUTH         hdr_auth;
	RPC_AUTH_VERIFIER auth_verifier;
	RPC_AUTH_NTLMSSP_NEG ntlmssp_neg;

	struct ntuser_creds *usr;
	usr = (struct ntuser_creds*)cli_conn_get_auth_creds(con);

	if (usr == NULL)
	{
		DEBUG(10,("create_ntlmssp_bind_req: NULL user creds\n"));
		return False;
	}

	prs_init(&rhdr     , 0x10, 4, False);
	prs_init(&rhdr_rb  , 0x0 , 4, False);
	prs_init(&rhdr_auth, 8   , 4, False);
	prs_init(&auth_req , 0x0 , 4, False);

	/* create the bind request RPC_HDR_RB */
	make_rpc_hdr_rb(&hdr_rb, 0x1630, 0x1630, 0x0,
	                0x1, 0x0, 0x1, abstract, transfer);

	/* stream the bind request data */
	smb_io_rpc_hdr_rb("", &hdr_rb,  &rhdr_rb, 0);

	make_rpc_hdr_auth(&hdr_auth, 0x0a, 0x06, 0x00, 1);
	smb_io_rpc_hdr_auth("hdr_auth", &hdr_auth, &rhdr_auth, 0);

	make_rpc_auth_verifier(&auth_verifier,
			       "NTLMSSP", NTLMSSP_NEGOTIATE);

	smb_io_rpc_auth_verifier("auth_verifier", &auth_verifier, &auth_req, 0);

	make_rpc_auth_ntlmssp_neg(&ntlmssp_neg,
			       usr->ntlmssp_flags, global_myname, usr->domain);

	smb_io_rpc_auth_ntlmssp_neg("ntlmssp_neg", &ntlmssp_neg, &auth_req, 0);

	/* create the request RPC_HDR */
	make_rpc_hdr(&hdr, RPC_BIND, 0x0, rpc_call_id,
	             auth_req .offset + rhdr_auth.offset +
	             rhdr_rb.offset + 0x10,
	             auth_req .offset);

	smb_io_rpc_hdr("hdr"   , &hdr   , &rhdr, 0);

	if (rhdr.data == NULL || rhdr_rb.data == NULL) return False;

	/***/
	/*** link rpc header, bind ack and auth responses ***/
	/***/

	prs_link(NULL      , &rhdr      , &rhdr_rb  );
	prs_link(&rhdr     , &rhdr_rb   , &rhdr_auth);
	prs_link(&rhdr_rb  , &rhdr_auth , &auth_req );
	prs_link(&rhdr_auth, &auth_req  , NULL      );

	prs_init(data, prs_buf_len(&rhdr), 4, False);
	prs_buf_copy(data->data, &rhdr, 0, prs_buf_len(&rhdr));

	prs_free_data(&rhdr     );
	prs_free_data(&rhdr_rb  );
	prs_free_data(&rhdr_auth);
	prs_free_data(&auth_req );

	return cli_conn_set_auth_info(con,
	             (void*)malloc(sizeof(struct ntlmssp_auth_struct)));
}

static BOOL decode_ntlmssp_bind_resp(struct cli_connection *con,
				prs_struct *rdata)
{
	BOOL valid_ack = True;

	ntlmssp_auth_struct *a;
	a = (ntlmssp_auth_struct *)cli_conn_get_auth_info(con);

	if (a == NULL)
	{
		return False;
	}

	if (valid_ack)
	{
		RPC_HDR_AUTH rhdr_auth;
		smb_io_rpc_hdr_auth("", &rhdr_auth, rdata, 0);
		if (rdata->offset == 0 ||
		    !rpc_hdr_ntlmssp_auth_chk(&rhdr_auth))
		{
			valid_ack = False;
		}
	}
	if (valid_ack)
	{
		RPC_AUTH_VERIFIER rhdr_verf;
		smb_io_rpc_auth_verifier("", &rhdr_verf, rdata, 0);
		if (rdata->offset == 0 ||
		    !rpc_auth_verifier_chk(&rhdr_verf,
		                                   "NTLMSSP",
		                                    NTLMSSP_CHALLENGE))
		{
			valid_ack = False;
		}
	}
	if (valid_ack)
	{
		smb_io_rpc_auth_ntlmssp_chal("", &a->ntlmssp_chal, rdata, 0);
		if (rdata->offset == 0) valid_ack = False;
	}
	return valid_ack;
}

/*******************************************************************
 creates a DCE/RPC bind authentication response

 - initialises the parse structure.
 - dynamically allocates the header data structure
 - caller is expected to free the header data structure once used.

 ********************************************************************/
static BOOL create_ntlmssp_rpc_bind_resp(struct pwd_info *pwd,
				char *domain, char *user_name, char *my_name,
				uint32 ntlmssp_cli_flgs,
				uint32 rpc_call_id,
				prs_struct *rhdr,
                                prs_struct *rhdr_autha,
                                prs_struct *auth_resp)
{
	RPC_HDR           hdr;
	RPC_HDR_AUTHA     hdr_autha;
	RPC_AUTH_VERIFIER auth_verifier;

	make_rpc_hdr_autha(&hdr_autha, 0x1630, 0x1630, 0x0a, 0x06, 0x00);
	smb_io_rpc_hdr_autha("hdr_autha", &hdr_autha, rhdr_autha, 0);
	prs_realloc_data(rhdr_autha, rhdr_autha->offset);

	make_rpc_auth_verifier(&auth_verifier,
			       "NTLMSSP", NTLMSSP_AUTH);

	smb_io_rpc_auth_verifier("auth_verifier", &auth_verifier, auth_resp, 0);
	prs_realloc_data(auth_resp, auth_resp->offset);

	create_ntlmssp_resp(pwd, domain, user_name, my_name, ntlmssp_cli_flgs,
                                auth_resp);

	/* create the request RPC_HDR */
	make_rpc_hdr(&hdr, RPC_BINDRESP, 0x0, rpc_call_id,
	             auth_resp->offset + rhdr_autha->offset + 0x10,
	             auth_resp->offset);

	smb_io_rpc_hdr("hdr"   , &hdr   , rhdr, 0);
	prs_realloc_data(rhdr, rhdr->offset);

	if (rhdr->data == NULL || rhdr_autha->data == NULL) return False;

	/***/
	/*** link rpc header and authentication responses ***/
	/***/

	prs_link(NULL      , rhdr       , rhdr_autha);
	prs_link(rhdr      , rhdr_autha , auth_resp );
	prs_link(rhdr_autha, auth_resp  , NULL );

	return True;
}

/*******************************************************************
 creates a DCE/RPC bind continue request

 - initialises the parse structure.
 - dynamically allocates the header data structure
 - caller is expected to free the header data structure once used.

 ********************************************************************/
static BOOL create_ntlmssp_bind_cont(struct cli_connection *con,
				prs_struct *dataa,
				uint32 rpc_call_id)
{
	BOOL ret = False;

	unsigned char p24[24];
	unsigned char lm_owf[24];
	unsigned char lm_hash[16];
	unsigned char usr_sess_key[16];

	prs_struct hdra;
	prs_struct hdr_autha;
	prs_struct auth_resp;

	struct ntuser_creds *usr;
	ntlmssp_auth_struct *a;
	a = (ntlmssp_auth_struct *)cli_conn_get_auth_info(con);
	usr = (struct ntuser_creds*)cli_conn_get_auth_creds(con);

	DEBUG(5,("Bind RPC Cont\n"));

	if (a == NULL)
	{
		return False;
	}

	prs_init(&hdra     , 0x10, 4, False);
	prs_init(&hdr_autha, 0x0, 4, False);
	prs_init(&auth_resp, 0x0, 4, False);

	pwd_make_lm_nt_owf(&usr->pwd, a->ntlmssp_chal.challenge, usr_sess_key);

	create_ntlmssp_rpc_bind_resp(&usr->pwd, usr->domain,
			     usr->user_name, global_myname,
			     a->ntlmssp_chal.neg_flags,
			     rpc_call_id,
			     &hdra, &hdr_autha, &auth_resp);
			    
	cli_set_con_usr_sesskey(con, usr_sess_key);
	pwd_get_lm_nt_owf(&usr->pwd, lm_owf, NULL, NULL);
	pwd_get_lm_nt_16(&usr->pwd, lm_hash, NULL);
	NTLMSSPOWFencrypt(lm_hash, lm_owf, p24);
	{
		unsigned char j = 0;
		int ind;
		unsigned char k2[8];

		memcpy(k2, p24, 5);
		k2[5] = 0xe5;
		k2[6] = 0x38;
		k2[7] = 0xb0;

		for (ind = 0; ind < 256; ind++)
		{
			a->ntlmssp_hash[ind] = (unsigned char)ind;
		}

		for (ind = 0; ind < 256; ind++)
		{
			unsigned char tc;

			j += (a->ntlmssp_hash[ind] + k2[ind%8]);

			tc = a->ntlmssp_hash[ind];
			a->ntlmssp_hash[ind] = a->ntlmssp_hash[j];
			a->ntlmssp_hash[j] = tc;
		}

		a->ntlmssp_hash[256] = 0;
		a->ntlmssp_hash[257] = 0;
	}
	bzero(lm_hash, sizeof(lm_hash));

	prs_init(dataa, 0, 4, False);
	ret = prs_copy(dataa, &hdra);

	prs_free_data(&hdra);
	prs_free_data(&hdr_autha);
	prs_free_data(&auth_resp);

	return ret;
}

cli_auth_fns cli_ntlmssp_fns =
{
	create_ntlmssp_bind_req,
	decode_ntlmssp_bind_resp,
	create_ntlmssp_bind_cont,
	create_ntlmssp_pdu,
	decode_ntlmssp_pdu
};
