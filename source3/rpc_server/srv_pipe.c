
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

static void NTLMSSPcalc_p( pipes_struct *p, unsigned char *data, int len)
{
    unsigned char *hash = p->ntlmssp_hash;
    unsigned char index_i = hash[256];
    unsigned char index_j = hash[257];
    int ind;

    for( ind = 0; ind < len; ind++)
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

/*******************************************************************
 turns a DCE/RPC request into a DCE/RPC reply

 this is where the data really should be split up into an array of
 headers and data sections.

 ********************************************************************/
BOOL create_rpc_reply(pipes_struct *p,
				uint32 data_start, uint32 data_end)
{
	char *data;
	BOOL auth_verify = IS_BITS_SET_ALL(p->ntlmssp_chal.neg_flags, NTLMSSP_NEGOTIATE_SIGN);
	BOOL auth_seal   = IS_BITS_SET_ALL(p->ntlmssp_chal.neg_flags, NTLMSSP_NEGOTIATE_SEAL);
	uint32 data_len;
	uint32 auth_len;

	DEBUG(5,("create_rpc_reply: data_start: %d data_end: %d max_tsize: %d\n",
	          data_start, data_end, p->hdr_ba.bba.max_tsize));

	auth_len = p->hdr.auth_len;

	if (p->ntlmssp_auth)
	{
		DEBUG(10,("create_rpc_reply: auth\n"));
		if (auth_len != 16)
		{
			return False;
		}
	}

	prs_init(&p->rhdr , 0x18, 4, 0, False);
	prs_init(&p->rauth, 1024, 4, 0, False);
	prs_init(&p->rverf, 0x10, 4, 0, False);

	p->hdr.pkt_type = RPC_RESPONSE; /* mark header as an rpc response */

	/* set up rpc header (fragmentation issues) */
	if (data_start == 0)
	{
		p->hdr.flags = RPC_FLG_FIRST;
	}
	else
	{
		p->hdr.flags = 0;
	}

	p->hdr_resp.alloc_hint = data_end - data_start; /* calculate remaining data to be sent */

	if (p->hdr_resp.alloc_hint + 0x18 <= p->hdr_ba.bba.max_tsize)
	{
		p->hdr.flags |= RPC_FLG_LAST;
		p->hdr.frag_len = p->hdr_resp.alloc_hint + 0x18;
	}
	else
	{
		p->hdr.frag_len = p->hdr_ba.bba.max_tsize;
	}

	if (p->ntlmssp_auth)
	{
		p->hdr_resp.alloc_hint -= auth_len + 8;
	}

	if (p->ntlmssp_auth)
	{
		data_len = p->hdr.frag_len - auth_len - (auth_verify ? 8 : 0) - 0x18;
	}
	else
	{
		data_len = p->hdr.frag_len - 0x18;
	}

	p->rhdr.data->offset.start = 0;
	p->rhdr.data->offset.end   = 0x18;

	/* store the header in the data stream */
	smb_io_rpc_hdr     ("hdr" , &(p->hdr     ), &(p->rhdr), 0);
	smb_io_rpc_hdr_resp("resp", &(p->hdr_resp), &(p->rhdr), 0);

	/* don't use rdata: use rdata_i instead, which moves... */
	/* make a pointer to the rdata data, NOT A COPY */

	p->rdata_i.data = NULL;
	prs_init(&p->rdata_i, 0, p->rdata.align, p->rdata.data->margin, p->rdata.io);
	data = mem_data(&(p->rdata.data), data_start);
	mem_create(p->rdata_i.data, data, 0, data_len, 0, False); 
	p->rdata_i.offset = data_len;

	if (auth_len > 0)
	{
		uint32 crc32 = 0;

		DEBUG(5,("create_rpc_reply: sign: %s seal: %s data %d auth %d\n",
			 BOOLSTR(auth_verify), BOOLSTR(auth_seal), data_len, auth_len));

		if (auth_seal)
		{
			crc32 = crc32_calc_buffer(data_len, data);
			NTLMSSPcalc_p(p, (uchar*)data, data_len);
		}

		if (auth_seal || auth_verify)
		{
			make_rpc_hdr_auth(&p->auth_info, 0x0a, 0x06, 0x08, (auth_verify ? 1 : 0));
			smb_io_rpc_hdr_auth("hdr_auth", &p->auth_info, &p->rauth, 0);
		}

		if (auth_verify)
		{
			char *auth_data;
			p->ntlmssp_seq_num++;
			make_rpc_auth_ntlmssp_chk(&p->ntlmssp_chk, NTLMSSP_SIGN_VERSION, crc32, p->ntlmssp_seq_num++);
			smb_io_rpc_auth_ntlmssp_chk("auth_sign", &(p->ntlmssp_chk), &p->rverf, 0);
			auth_data = mem_data(&p->rverf.data, 4);
			NTLMSSPcalc_p(p, (uchar*)auth_data, 12);
		}
	}

	/* set up the data chain */
	if (p->ntlmssp_auth)
	{
		prs_link(NULL       , &p->rhdr   , &p->rdata_i);
		prs_link(&p->rhdr   , &p->rdata_i, &p->rauth  );
		prs_link(&p->rdata_i, &p->rauth  , &p->rverf  );
		prs_link(&p->rauth  , &p->rverf  , NULL       );
	}
	else
	{
		prs_link(NULL    , &p->rhdr   , &p->rdata_i);
		prs_link(&p->rhdr, &p->rdata_i, NULL       );
	}

	return p->rhdr.data != NULL && p->rhdr.offset == 0x18;
}

static BOOL api_pipe_ntlmssp_verify(pipes_struct *p)
{
	uchar *pwd = NULL;
	uchar null_pwd[16];
	uchar lm_owf[24];
	uchar nt_owf[128];
	size_t lm_owf_len;
	size_t nt_owf_len;
	size_t usr_len;
	size_t dom_len;
	size_t wks_len;
	BOOL anonymous = False;

	struct smb_passwd *smb_pass = NULL;
	
	user_struct *vuser = get_valid_user_struct(p->vuid);

	memset(null_pwd, 0, sizeof(null_pwd));

	DEBUG(5,("api_pipe_ntlmssp_verify: checking user details\n"));

	if (vuser == NULL)
	{
		DEBUG(0,("get user struct %d failed\n", p->vuid));
		return False;
	}

	lm_owf_len = p->ntlmssp_resp.hdr_lm_resp.str_str_len;
	nt_owf_len = p->ntlmssp_resp.hdr_nt_resp.str_str_len;
	usr_len    = p->ntlmssp_resp.hdr_usr    .str_str_len;
	dom_len    = p->ntlmssp_resp.hdr_domain .str_str_len;
	wks_len    = p->ntlmssp_resp.hdr_wks    .str_str_len;

	if (lm_owf_len == 0 && nt_owf_len == 0 &&
	    usr_len == 0 && dom_len == 0 && wks_len == 0)
	{
		anonymous = True;
	}
	else
	{
		if (lm_owf_len == 0) return False;
		if (nt_owf_len == 0) return False;
		if (p->ntlmssp_resp.hdr_usr    .str_str_len == 0) return False;
		if (p->ntlmssp_resp.hdr_domain .str_str_len == 0) return False;
		if (p->ntlmssp_resp.hdr_wks    .str_str_len == 0) return False;
	}

	if (lm_owf_len > sizeof(lm_owf)) return False;
	if (nt_owf_len > sizeof(nt_owf)) return False;

	memcpy(lm_owf, p->ntlmssp_resp.lm_resp, sizeof(lm_owf));
	memcpy(nt_owf, p->ntlmssp_resp.nt_resp, sizeof(nt_owf));

#ifdef DEBUG_PASSWORD
	DEBUG(100,("lm, nt owfs, chal\n"));
	dump_data(100, lm_owf, sizeof(lm_owf));
	dump_data(100, nt_owf, sizeof(nt_owf));
	dump_data(100, p->ntlmssp_chal.challenge, 8);
#endif

	memset(p->user_name, 0, sizeof(p->user_name));
	memset(p->domain   , 0, sizeof(p->domain   ));
	memset(p->wks      , 0, sizeof(p->wks      ));

	if (IS_BITS_SET_ALL(p->ntlmssp_chal.neg_flags, NTLMSSP_NEGOTIATE_UNICODE))
	{
		unibuf_to_ascii(p->user_name, p->ntlmssp_resp.user,
				MIN(p->ntlmssp_resp.hdr_usr   .str_str_len/2,
				    sizeof(p->user_name)-1));
		unibuf_to_ascii(p->domain   , p->ntlmssp_resp.domain,
				MIN(p->ntlmssp_resp.hdr_domain.str_str_len/2,
				    sizeof(p->domain   )-1));
		unibuf_to_ascii(p->wks      , p->ntlmssp_resp.wks,
				MIN(p->ntlmssp_resp.hdr_wks   .str_str_len/2,
				    sizeof(p->wks      )-1));
	}
	else
	{
		fstrcpy(p->user_name, p->ntlmssp_resp.user  );
		fstrcpy(p->domain   , p->ntlmssp_resp.domain);
		fstrcpy(p->wks      , p->ntlmssp_resp.wks   );
	}


	if (anonymous)
	{
		DEBUG(5,("anonymous user session\n"));
		mdfour(vuser->dc.user_sess_key, null_pwd, 16);
		pwd = null_pwd;
		p->ntlmssp_validated = True;
	}
	else
	{
		DEBUG(5,("user: %s domain: %s wks: %s\n", p->user_name, p->domain, p->wks));
		become_root(True);
		smb_pass = getsmbpwnam(p->user_name);
		p->ntlmssp_validated = pass_check_smb(smb_pass, p->domain,
				      (uchar*)p->ntlmssp_chal.challenge,
				      lm_owf, lm_owf_len,
				      nt_owf, nt_owf_len,
				      NULL, vuser->dc.user_sess_key);
		unbecome_root(True);

		if (smb_pass != NULL)
		{
			pwd = smb_pass->smb_passwd;
		}
	}

	if (p->ntlmssp_validated && pwd != NULL)
	{
		uchar p24[24];
		NTLMSSPOWFencrypt(pwd, lm_owf, p24);
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
				p->ntlmssp_hash[ind] = (unsigned char)ind;
			}

			for( ind = 0; ind < 256; ind++)
			{
				unsigned char tc;

				j += (p->ntlmssp_hash[ind] + k2[ind%8]);

				tc = p->ntlmssp_hash[ind];
				p->ntlmssp_hash[ind] = p->ntlmssp_hash[j];
				p->ntlmssp_hash[j] = tc;
			}

			p->ntlmssp_hash[256] = 0;
			p->ntlmssp_hash[257] = 0;
		}
		p->ntlmssp_seq_num = 0;
	}
	else
	{
		p->ntlmssp_validated = False;
	}

	return p->ntlmssp_validated;
}

static BOOL api_pipe_ntlmssp(pipes_struct *p, prs_struct *pd)
{
	/* receive a negotiate; send a challenge; receive a response */
	switch (p->auth_verifier.msg_type)
	{
		case NTLMSSP_NEGOTIATE:
		{
			smb_io_rpc_auth_ntlmssp_neg("", &p->ntlmssp_neg, pd, 0);
			break;
		}
		case NTLMSSP_AUTH:
		{
			smb_io_rpc_auth_ntlmssp_resp("", &p->ntlmssp_resp, pd, 0);
			if (!api_pipe_ntlmssp_verify(p))
			{
				pd->offset = 0;
			}
			break;
		}
		default:
		{
			/* NTLMSSP expected: unexpected message type */
			DEBUG(3,("unexpected message type in NTLMSSP %d\n",
			          p->auth_verifier.msg_type));
			return False;
		}
	}

	return (pd->offset != 0);
}

struct api_cmd
{
  char * pipe_clnt_name;
  char * pipe_srv_name;
  BOOL (*fn) (pipes_struct *, prs_struct *);
};

static struct api_cmd **api_fd_commands = NULL;
uint32 num_cmds = 0;

static void api_cmd_free(struct api_cmd *item)
{
	if (item != NULL)
	{
		if (item->pipe_clnt_name != NULL)
		{
			free(item->pipe_clnt_name);
		}
		if (item->pipe_srv_name != NULL)
		{
			free(item->pipe_srv_name);
		}
		free(item);
	}
}

static struct api_cmd *api_cmd_dup(const struct api_cmd *from)
{
	struct api_cmd *copy = NULL;
	if (from == NULL)
	{
		return NULL;
	}
	copy = (struct api_cmd *) malloc(sizeof(struct api_cmd));
	if (copy != NULL)
	{
		ZERO_STRUCTP(copy);
		if (from->pipe_clnt_name != NULL)
		{
			copy->pipe_clnt_name  = strdup(from->pipe_clnt_name );
		}
		if (from->pipe_srv_name != NULL)
		{
			copy->pipe_srv_name = strdup(from->pipe_srv_name);
		}
		if (from->fn != NULL)
		{
			copy->fn    = from->fn;
		}
	}
	return copy;
}

static void free_api_cmd_array(uint32 num_entries, struct api_cmd **entries)
{
	void(*fn)(void*) = (void(*)(void*))&api_cmd_free;
	free_void_array(num_entries, (void**)entries, *fn);
}

static struct api_cmd* add_api_cmd_to_array(uint32 *len,
				struct api_cmd ***array,
				const struct api_cmd *name)
{
	void*(*fn)(const void*) = (void*(*)(const void*))&api_cmd_dup;
	return (struct api_cmd*)add_copy_to_array(len,
	                     (void***)array, (const void*)name, *fn, False);
				
}

#if 0
{
    { "lsarpc",   "lsass",   api_ntlsa_rpc },
    { "samr",     "lsass",   api_samr_rpc },
    { "srvsvc",   "ntsvcs",  api_srvsvc_rpc },
    { "wkssvc",   "ntsvcs",  api_wkssvc_rpc },
    { "browser",  "ntsvcs",  api_brs_rpc },
    { "svcctl",   "ntsvcs",  api_svcctl_rpc },
    { "NETLOGON", "lsass",   api_netlog_rpc },
    { "winreg",   "winreg",  api_reg_rpc },
    { "spoolss",  "spoolss", api_spoolss_rpc },
    { NULL,       NULL,      NULL }
};
#endif

void close_msrpc_command_processor(void)
{
	free_api_cmd_array(num_cmds, api_fd_commands);
}

void add_msrpc_command_processor(char* pipe_name,
				char* process_name,
				BOOL (*fn) (pipes_struct *, prs_struct *))
{
	struct api_cmd cmd = { pipe_name, process_name, fn };
	add_api_cmd_to_array(&num_cmds, &api_fd_commands, &cmd);
}

static BOOL api_pipe_bind_auth_resp(pipes_struct *p, prs_struct *pd)
{
	DEBUG(5,("api_pipe_bind_auth_resp: decode request. %d\n", __LINE__));

	if (p->hdr.auth_len == 0) return False;

	/* decode the authentication verifier response */
	smb_io_rpc_hdr_autha("", &p->autha_info, pd, 0);
	if (pd->offset == 0) return False;

	if (!rpc_hdr_auth_chk(&(p->auth_info))) return False;

	smb_io_rpc_auth_ntlmssp_verifier("", &p->auth_verifier, pd, 0);
	if (pd->offset == 0) return False;

	if (!rpc_auth_ntlmssp_verifier_chk(&(p->auth_verifier), "NTLMSSP", NTLMSSP_AUTH)) return False;
	
	return api_pipe_ntlmssp(p, pd);
}

static BOOL api_pipe_fault_resp(pipes_struct *p, prs_struct *pd, uint32 status)
{
	DEBUG(5,("api_pipe_fault_resp: make response\n"));

	prs_init(&(p->rhdr     ), 0x18, 4, 0, False);
	prs_init(&(p->rfault   ), 0x8 , 4, 0, False);

	/***/
	/*** set up the header, response header and fault status ***/
	/***/

	p->hdr_fault.status   = status;
	p->hdr_fault.reserved = 0x0;

	p->hdr_resp.alloc_hint   = 0x0;
	p->hdr_resp.cancel_count = 0x0;
	p->hdr_resp.reserved     = 0x0;

	make_rpc_hdr(&p->hdr, RPC_FAULT, RPC_FLG_NOCALL | RPC_FLG_FIRST | RPC_FLG_LAST,
	             p->hdr.call_id,
	             0x20,
	             0);

	smb_io_rpc_hdr      ("hdr"  , &(p->hdr      ), &(p->rhdr), 0);
	smb_io_rpc_hdr_resp ("resp" , &(p->hdr_resp ), &(p->rhdr), 0);
	smb_io_rpc_hdr_fault("fault", &(p->hdr_fault), &(p->rfault), 0);
	mem_realloc_data(p->rhdr.data, p->rhdr.offset);
	mem_realloc_data(p->rfault.data, p->rfault.offset);

	/***/
	/*** link rpc header and fault together ***/
	/***/

	prs_link(NULL    , &p->rhdr  , &p->rfault);
	prs_link(&p->rhdr, &p->rfault, NULL      );

	return True;
}

static BOOL api_pipe_bind_and_alt_req(pipes_struct *p, prs_struct *pd, enum RPC_PKT_TYPE pkt_type)
{
	uint16 assoc_gid;
	fstring ack_pipe_name;
	int i = 0;

	p->ntlmssp_auth = False;

	DEBUG(5,("api_pipe_bind_req: decode request. %d\n", __LINE__));

	for (i = 0; i < num_cmds; i++)
	{
		if (strequal(api_fd_commands[i]->pipe_clnt_name, p->name) &&
		    api_fd_commands[i]->fn != NULL)
		{
			DEBUG(3,("api_pipe_bind_req: \\PIPE\\%s -> \\PIPE\\%s\n",
			           api_fd_commands[i]->pipe_clnt_name,
			           api_fd_commands[i]->pipe_srv_name));
			fstrcpy(p->pipe_srv_name, api_fd_commands[i]->pipe_srv_name);
			break;
		}
	}

	if (api_fd_commands[i]->fn == NULL) return False;

	/* decode the bind request */
	smb_io_rpc_hdr_rb("", &p->hdr_rb, pd, 0);

	if (pd->offset == 0) return False;

	if (p->hdr.auth_len != 0)
	{
		/* decode the authentication verifier */
		smb_io_rpc_hdr_auth    ("", &p->auth_info    , pd, 0);
		if (pd->offset == 0) return False;

		p->ntlmssp_auth = p->auth_info.auth_type = 0x0a;

		if (p->ntlmssp_auth)
		{
			smb_io_rpc_auth_ntlmssp_verifier("", &p->auth_verifier, pd, 0);
			if (pd->offset == 0) return False;

			p->ntlmssp_auth = strequal(p->auth_verifier.signature, "NTLMSSP");
		}

		if (p->ntlmssp_auth)
		{
			if (!api_pipe_ntlmssp(p, pd)) return False;
		}
	}

	switch (pkt_type)
	{
		case RPC_BINDACK:
		{
			/* name has to be \PIPE\xxxxx */
			fstrcpy(ack_pipe_name, "\\PIPE\\");
			fstrcat(ack_pipe_name, p->pipe_srv_name);
			break;
		}
		case RPC_ALTCONTRESP:
		{
			/* secondary address CAN be NULL
			 * as the specs says it's ignored.
			 * It MUST NULL to have the spoolss working.
			 */
			fstrcpy(ack_pipe_name, "");
			break;
		}
		default:
		{
			return False;
		}
	}

	DEBUG(5,("api_pipe_bind_req: make response. %d\n", __LINE__));

	prs_init(&(p->rdata), 1024, 4, 0, False);
	prs_init(&(p->rhdr ), 0x18, 4, 0, False);
	prs_init(&(p->rauth), 1024, 4, 0, False);
	prs_init(&(p->rverf), 0x08, 4, 0, False);
	prs_init(&(p->rntlm), 1024, 4, 0, False);

	/***/
	/*** do the bind ack first ***/
	/***/

	if (p->ntlmssp_auth)
	{
		assoc_gid = 0x7a77;
	}
	else
	{
		assoc_gid = p->hdr_rb.bba.assoc_gid;
	}

	make_rpc_hdr_ba(&p->hdr_ba,
	                p->hdr_rb.bba.max_tsize,
	                p->hdr_rb.bba.max_rsize,
	                assoc_gid,
	                ack_pipe_name,
	                0x1, 0x0, 0x0,
	                &(p->hdr_rb.transfer));

	smb_io_rpc_hdr_ba("", &p->hdr_ba, &p->rdata, 0);
	mem_realloc_data(p->rdata.data, p->rdata.offset);

	/***/
	/*** now the authentication ***/
	/***/

	if (p->ntlmssp_auth)
	{
		uint8 challenge[8];
		generate_random_buffer(challenge, 8, False);

		/*** authentication info ***/

		make_rpc_hdr_auth(&p->auth_info, 0x0a, 0x06, 0, 1);
		smb_io_rpc_hdr_auth("", &p->auth_info, &p->rverf, 0);
		mem_realloc_data(p->rverf.data, p->rverf.offset);

		/*** NTLMSSP verifier ***/

		make_rpc_auth_ntlmssp_verifier(&p->auth_verifier,
		                       "NTLMSSP", NTLMSSP_CHALLENGE);
		smb_io_rpc_auth_ntlmssp_verifier("", &p->auth_verifier, &p->rauth, 0);
		mem_realloc_data(p->rauth.data, p->rauth.offset);

		/* NTLMSSP challenge ***/

		make_rpc_auth_ntlmssp_chal(&p->ntlmssp_chal,
		                           0x000082b1, challenge);
		smb_io_rpc_auth_ntlmssp_chal("", &p->ntlmssp_chal, &p->rntlm, 0);
		mem_realloc_data(p->rntlm.data, p->rntlm.offset);
	}

	/***/
	/*** then do the header, now we know the length ***/
	/***/

	make_rpc_hdr(&p->hdr, pkt_type, RPC_FLG_FIRST | RPC_FLG_LAST,
	             p->hdr.call_id,
	             p->rdata.offset + p->rverf.offset + p->rauth.offset + p->rntlm.offset + 0x10,
	             p->rauth.offset + p->rntlm.offset);

	smb_io_rpc_hdr("", &p->hdr, &p->rhdr, 0);
	mem_realloc_data(p->rhdr.data, p->rdata.offset);

	/***/
	/*** link rpc header, bind acknowledgment and authentication responses ***/
	/***/

	if (p->ntlmssp_auth)
	{
		prs_link(NULL     , &p->rhdr , &p->rdata);
		prs_link(&p->rhdr , &p->rdata, &p->rverf);
		prs_link(&p->rdata, &p->rverf, &p->rauth);
		prs_link(&p->rverf, &p->rauth, &p->rntlm);
		prs_link(&p->rauth, &p->rntlm, NULL     );
	}
	else
	{
		prs_link(NULL    , &p->rhdr , &p->rdata);
		prs_link(&p->rhdr, &p->rdata, NULL     );
	}

	return True;
}

/*
 * The RPC Alter-Context call is used only by the spoolss pipe
 * simply because there is a bug (?) in the MS unmarshalling code
 * or in the marshalling code. If it's in the later, then Samba
 * have the same bug.
 */
static BOOL api_pipe_bind_req(pipes_struct *p, prs_struct *pd)
{
	return api_pipe_bind_and_alt_req(p, pd, RPC_BINDACK);
}

static BOOL api_pipe_alt_req(pipes_struct *p, prs_struct *pd)
{
	return api_pipe_bind_and_alt_req(p, pd, RPC_ALTCONTRESP);
}

static BOOL api_pipe_auth_process(pipes_struct *p, prs_struct *pd)
{
	BOOL auth_verify = IS_BITS_SET_ALL(p->ntlmssp_chal.neg_flags, NTLMSSP_NEGOTIATE_SIGN);
	BOOL auth_seal   = IS_BITS_SET_ALL(p->ntlmssp_chal.neg_flags, NTLMSSP_NEGOTIATE_SEAL);
	int data_len;
	int auth_len;
	uint32 old_offset;
	uint32 crc32 = 0;

	auth_len = p->hdr.auth_len;

	if (auth_len != 16 && auth_verify)
	{
		return False;
	}

	data_len = p->hdr.frag_len - auth_len - (auth_verify ? 8 : 0) - 0x18;
	
	DEBUG(5,("api_pipe_auth_process: sign: %s seal: %s data %d auth %d\n",
	         BOOLSTR(auth_verify), BOOLSTR(auth_seal), data_len, auth_len));

	if (auth_seal)
	{
		char *data = mem_data(&pd->data, pd->offset);
		DEBUG(5,("api_pipe_auth_process: data %d\n", pd->offset));
		NTLMSSPcalc_p(p, (uchar*)data, data_len);
		crc32 = crc32_calc_buffer(data_len, data);
	}

	/*** skip the data, record the offset so we can restore it again */
	old_offset = pd->offset;

	if (auth_seal || auth_verify)
	{
		pd->offset += data_len;
		smb_io_rpc_hdr_auth("hdr_auth", &p->auth_info, pd, 0);
	}

	if (auth_verify)
	{
		char *req_data = mem_data(&pd->data, pd->offset + 4);
		DEBUG(5,("api_pipe_auth_process: auth %d\n", pd->offset + 4));
		NTLMSSPcalc_p(p, (uchar*)req_data, 12);
		smb_io_rpc_auth_ntlmssp_chk("auth_sign", &(p->ntlmssp_chk), pd, 0);

		if (!rpc_auth_ntlmssp_chk(&(p->ntlmssp_chk), crc32,
		                          p->ntlmssp_seq_num))
		{
			return False;
		}
	}

	pd->offset = old_offset;

	return True;
}

static BOOL api_pipe_request(pipes_struct *p, prs_struct *pd)
{
	int i = 0;

	if (p->ntlmssp_auth && p->ntlmssp_validated)
	{
		if (!api_pipe_auth_process(p, pd)) return False;

		DEBUG(0,("api_pipe_request: **** MUST CALL become_user() HERE **** \n"));
#if 0
		become_user();
#endif
	}

	for (i = 0; i < num_cmds; i++)
	{
		if (strequal(api_fd_commands[i]->pipe_clnt_name, p->name) &&
		    api_fd_commands[i]->fn != NULL)
		{
			DEBUG(3,("Doing \\PIPE\\%s\n", api_fd_commands[i]->pipe_clnt_name));
			return api_fd_commands[i]->fn(p, pd);
		}
	}
	return False;
}

BOOL rpc_command(pipes_struct *p, prs_struct *pd)
{
	BOOL reply = False;
	DEBUG(10,("rpc_command\n"));

	if (p->m != NULL)
	{
		DEBUG(10,("msrpc redirect\n"));
		if (!msrpc_send_prs(p->m, pd))
		{
			DEBUG(2,("msrpc redirect send failed\n"));
			return False;
		}
		if (!msrpc_receive_prs(p->m, &p->rhdr))
		{
			DEBUG(2,("msrpc redirect receive failed\n"));
			return False;
		}
		prs_link(NULL, &p->rhdr, NULL);
		prs_debug_out(&p->rhdr, 10);
		return True;
	}

	if (pd->data == NULL) return False;

	/* process the rpc header */
	smb_io_rpc_hdr("", &p->hdr, pd, 0);

	if (pd->offset == 0) return False;

	switch (p->hdr.pkt_type)
	{
		case RPC_BIND   :
		{
			reply = api_pipe_bind_req(p, pd);
			break;
		}
		case RPC_ALTCONT:
		{
			reply = api_pipe_alt_req(p, pd);
 			break;
 		}
		case RPC_REQUEST:
		{
			if (p->ntlmssp_auth && !p->ntlmssp_validated)
			{
				/* authentication _was_ requested
				   and it failed.  sorry, no deal!
				 */
				reply = False;
			}
			else
			{
				/* read the rpc header */
				smb_io_rpc_hdr_req("req", &(p->hdr_req), pd, 0);
				reply = api_pipe_request(p, pd);
			}
			break;
		}
		case RPC_BINDRESP: /* not the real name! */
		{
			reply = api_pipe_bind_auth_resp(p, pd);
			p->ntlmssp_auth = reply;
			break;
		}
	}

	if (!reply)
	{
		reply = api_pipe_fault_resp(p, pd, 0x1c010002);
	}

	return reply;
}


/*******************************************************************
 receives a netlogon pipe and responds.
 ********************************************************************/
static BOOL api_rpc_command(pipes_struct *p, 
				char *rpc_name, struct api_struct *api_rpc_cmds,
				prs_struct *data)
{
	int fn_num;
	DEBUG(4,("api_rpc_command: %s op 0x%x - ", rpc_name, p->hdr_req.opnum));

	for (fn_num = 0; api_rpc_cmds[fn_num].name; fn_num++)
	{
		if (api_rpc_cmds[fn_num].opnum == p->hdr_req.opnum && api_rpc_cmds[fn_num].fn != NULL)
		{
			DEBUG(3,("api_rpc_command: %s\n", api_rpc_cmds[fn_num].name));
			break;
		}
	}

	if (api_rpc_cmds[fn_num].name == NULL)
	{
		DEBUG(4, ("unknown\n"));
		return False;
	}

	/* start off with 1024 bytes, and a large safety margin too */
	prs_init(&p->rdata, 1024, 4, SAFETY_MARGIN, False);

	/* do the actual command */
	api_rpc_cmds[fn_num].fn(p, data, &(p->rdata));

	if (p->rdata.data == NULL || p->rdata.offset == 0)
	{
		mem_free_data(p->rdata.data);
		return False;
	}

	mem_realloc_data(p->rdata.data, p->rdata.offset);

	DEBUG(10,("called %s\n", rpc_name));

	return True;
}


/*******************************************************************
 receives a netlogon pipe and responds.
 ********************************************************************/
BOOL api_rpcTNP(pipes_struct *p, char *rpc_name, struct api_struct *api_rpc_cmds,
				prs_struct *data)
{
	if (data == NULL || data->data == NULL)
	{
		DEBUG(2,("%s: NULL data received\n", rpc_name));
		return False;
	}

	/* interpret the command */
	if (!api_rpc_command(p, rpc_name, api_rpc_cmds, data))
	{
		return False;
	}

	/* create the rpc header */
	if (!create_rpc_reply(p, 0, p->rdata.offset + (p->ntlmssp_auth ? (16 + 8) : 0)))
	{
		return False;
	}

	return True;
}
