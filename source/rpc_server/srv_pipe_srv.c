
/* 
 *  Unix SMB/Netbios implementation.
 *  Version 1.9.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-2000
 *  Copyright (C) Luke Kenneth Casson Leighton 1996-2000,
 *  Copyright (C) Paul Ashton                  1997-2000.
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
#include "rpc_parse.h"
#include "nterr.h"

extern int DEBUGLEVEL;

/*******************************************************************
turns a DCE/RPC response stream into a DCE/RPC reply
********************************************************************/
static BOOL create_rpc_reply(rpcsrv_struct *l, uint32 data_start,
				prs_struct *resp)
{
	BOOL ret;

	if (l->auth != NULL)
	{
		ret = l->auth->api_create_pdu(l, data_start, resp);
	}
	else
	{
		ret = False;
	}
	if ((!ret) || IS_BITS_SET_ALL(l->hdr.flags, RPC_FLG_LAST))
	{
		DEBUG(10,("create_rpc_reply: finished sending\n"));
		prs_free_data(&l->rdata);
	}
	return ret;
}


struct api_cmd
{
  char * pipe_clnt_name;
  char * pipe_srv_name;
  BOOL (*fn) (rpcsrv_struct *);
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


void close_msrpc_command_processor(void)
{
	free_api_cmd_array(num_cmds, api_fd_commands);
}

void add_msrpc_command_processor(char* pipe_name,
				char* process_name,
				BOOL (*fn) (rpcsrv_struct *))
{
	struct api_cmd cmd;
	cmd.pipe_clnt_name = pipe_name;
	cmd.pipe_srv_name = process_name;
	cmd.fn = fn;

	add_api_cmd_to_array(&num_cmds, &api_fd_commands, &cmd);
}

static BOOL api_pipe_fault_resp(rpcsrv_struct *l, uint32 status,
				prs_struct *resp)
{
	prs_struct rhdr;
	prs_struct rfault;
	RPC_HDR_FAULT hdr_fault;
	RPC_HDR_RESP  hdr_resp;

	DEBUG(5,("api_pipe_fault_resp: make response\n"));

	if (l->auth_validated == False)
	{
		l->faulted_once_before = True;
	}

	prs_init(&(rhdr     ), 0, 4, False);
	prs_init(&(rfault   ), 0, 4, False);

	/***/
	/*** set up the header, response header and fault status ***/
	/***/

	hdr_fault.status   = status;
	hdr_fault.reserved = 0x0;

	hdr_resp.alloc_hint   = 0x0;
	hdr_resp.cancel_count = 0x0;
	hdr_resp.context_id   = 0x0;
	hdr_resp.reserved     = 0x0;

	make_rpc_hdr(&l->hdr, RPC_FAULT, RPC_FLG_NOCALL | RPC_FLG_FIRST | RPC_FLG_LAST,
	             l->hdr.call_id,
	             0x20,
	             0);

	smb_io_rpc_hdr      ("hdr"  , &(l->hdr      ), &(rhdr), 0);
	smb_io_rpc_hdr_resp ("resp" , &(hdr_resp ), &(rhdr), 0);
	smb_io_rpc_hdr_fault("fault", &(hdr_fault), &(rfault), 0);
	prs_realloc_data(&rhdr  , rhdr.offset  );
	prs_realloc_data(&rfault, rfault.offset);

	/***/
	/*** link rpc header and fault together ***/
	/***/

	prs_link(NULL    , &rhdr  , &rfault);
	prs_link(&rhdr, &rfault, NULL      );

	prs_init(resp, 0, 4, False);
	if (!prs_copy(resp, &rhdr)) return False;
	prs_free_data(&rfault);
	prs_free_data(&rhdr);

	return True;
}

static BOOL srv_pipe_bind_and_alt_req(rpcsrv_struct *l, 
				const char* ack_pipe_name,
				prs_struct *resp,
				enum RPC_PKT_TYPE pkt_type)
{
	BOOL ret;

	prs_struct rhdr;
	uint32 assoc_gid = l->key.pid;

	l->auth = NULL;

	/* decode the bind request */
	smb_io_rpc_hdr_rb("", &l->hdr_rb, &l->data_i, 0);

	if (l->data_i.offset == 0) return False;

	assoc_gid = l->hdr_rb.bba.assoc_gid;
	l->key.pid = assoc_gid;

	if (l->hdr.auth_len != 0)
	{
		RPC_HDR_AUTH  auth_info;
		BOOL found = False;
		int i;

		/* decode the authentication verifier */
		smb_io_rpc_hdr_auth    ("", &auth_info    , &l->data_i, 0);
		if (l->data_i.offset == 0) return False;

		for (i = 0; i < l->num_auths && !found; i++)
		{
			if (l->auth_fns[i]->api_is_auth(&auth_info,
			                                &l->auth_info))
			{
				l->auth = l->auth_fns[i];
				found = True;
			}
		}
		if (!found)
		{
			return False;
		}
	}
	else
	{
		extern srv_auth_fns noauth_fns;

		l->auth = &noauth_fns;
		l->auth_info = NULL;
		
		assoc_gid = l->hdr_rb.bba.assoc_gid;
		l->key.pid = assoc_gid;
	}

	if (l->auth != NULL)
	{
		if (!l->auth->api_auth_chk(l, pkt_type))
		{
			if (l->auth_info != NULL)
			{
				free(l->auth_info);
			}
			l->auth_info = NULL;
			return False;
		}
	}
	DEBUG(5,("api_pipe_bind_req: make response. %d\n", __LINE__));

	prs_init(&(l->rdata), 0, 4, False);
	prs_init(&(rhdr    ), 0, 4, False);

	/***/
	/*** do the bind ack first ***/
	/***/

	make_rpc_hdr_ba(&l->hdr_ba,
	                l->hdr_rb.bba.max_tsize,
	                l->hdr_rb.bba.max_rsize,
	                assoc_gid,
	                ack_pipe_name,
	                0x1, 0x0, 0x0,
	                &(l->hdr_rb.transfer));

	smb_io_rpc_hdr_ba("", &l->hdr_ba, &l->rdata, 0);
	prs_realloc_data(&l->rdata, l->rdata.offset);

	if (l->auth != NULL)
	{
		/***/
		/*** now the authentication ***/
		/***/

		ret = l->auth->api_auth_gen(l, resp, pkt_type);

		if (!ret)
		{
			free(l->auth_info);
			l->auth_info = NULL;
			prs_free_data(&l->rdata);
			return False;
		}
	}
	else
	{
		return False;
	}

	return ret;
}

static BOOL api_pipe_bind_and_alt_req(rpcsrv_struct *l, 
				const char* name,
				prs_struct *resp,
				enum RPC_PKT_TYPE pkt_type)
{
	fstring ack_pipe_name;
	fstring pipe_srv_name;
	int i = 0;

	DEBUG(5,("api_pipe_bind_req: decode request. %d\n", __LINE__));

	for (i = 0; i < num_cmds; i++)
	{
		if (strequal(api_fd_commands[i]->pipe_clnt_name, name) &&
		    api_fd_commands[i]->fn != NULL)
		{
			DEBUG(3,("api_pipe_bind_req: \\PIPE\\%s -> \\PIPE\\%s\n",
			           api_fd_commands[i]->pipe_clnt_name,
			           api_fd_commands[i]->pipe_srv_name));
			fstrcpy(pipe_srv_name, api_fd_commands[i]->pipe_srv_name);
			break;
		}
	}

	if (api_fd_commands[i]->fn == NULL) return False;

	switch (pkt_type)
	{
		case RPC_BINDACK:
		{
			/* name has to be \PIPE\xxxxx */
			fstrcpy(ack_pipe_name, "\\PIPE\\");
			fstrcat(ack_pipe_name, pipe_srv_name);
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
	return srv_pipe_bind_and_alt_req(l, ack_pipe_name, resp, pkt_type);
}

/*
 * The RPC Alter-Context call is used only by the spoolss pipe
 * simply because there is a bug (?) in the MS unmarshalling code
 * or in the marshalling code. If it's in the later, then Samba
 * have the same bug.
 */
static BOOL api_pipe_bind_req(rpcsrv_struct *l, const char* name, prs_struct *resp)
{
	return api_pipe_bind_and_alt_req(l, name, resp, RPC_BINDACK);
}

static BOOL api_pipe_alt_req(rpcsrv_struct *l, const char* name, prs_struct *resp)
{
	return api_pipe_bind_and_alt_req(l, name, resp, RPC_ALTCONTRESP);
}

static BOOL api_pipe_request(rpcsrv_struct *l, const char* name,
				prs_struct *resp)
{
	int i = 0;

	if (l->auth != NULL && l->auth_validated)
	{
		DEBUG(10,("api_pipe_request: validated auth\n"));
		if (!l->auth->api_decode_pdu(l)) return False;
	}

	for (i = 0; i < num_cmds; i++)
	{
		if (strequal(api_fd_commands[i]->pipe_clnt_name, name) &&
		    api_fd_commands[i]->fn != NULL)
		{
			DEBUG(3,("Doing \\PIPE\\%s\n", api_fd_commands[i]->pipe_clnt_name));
			if (!api_fd_commands[i]->fn(l))
			{
				return False;
			}
			l->rdata_offset = 0;

			/* create the rpc pdu */
			return create_rpc_reply(l, 0, resp);

		}
	}
	return False;
}

static BOOL rpc_redir_local(rpcsrv_struct *l, prs_struct *req, prs_struct *resp,
				const char* name)
{
	BOOL reply = False;
	BOOL last;
	BOOL first;

	if (req->data == NULL || req->data_size == 0)
	{
		if (l->rdata.data == NULL)
		{
			return False;
		}
		/* hmm, must need some more data.
		 * create, flatten and return data in a single pdu
		 */
		if (!create_rpc_reply(l, l->rdata_offset, resp)) return False;

		return True;
	}

	if (req->data == NULL) return False;

	/* lkclXXXX still assume that the first complete PDU is always
	   in a single request!!!
	 */
	/* process the rpc header */
	req->offset = 0x0;
	req->io = True;
	smb_io_rpc_hdr("hdr", &l->hdr, req, 0);

	if (req->offset == 0) return False;

	last  = IS_BITS_SET_ALL(l->hdr.flags, RPC_FLG_LAST);
	first = IS_BITS_SET_ALL(l->hdr.flags, RPC_FLG_FIRST);

	if (l->hdr.pkt_type == RPC_BIND ||
	    l->hdr.pkt_type == RPC_BINDRESP)
	{
		last = True;
		first = True;
	}

	if (first)
	{
		prs_init(&l->data_i, 0, 4, True);
	}
	if (last)
	{
		prs_append_data(&l->data_i,
		                prs_data(req, req->offset),
		                req->data_size - req->offset);
	}
	else
	{
		prs_init(resp, 0, 4, False);
		return True;
	}

	/* previous authentication failure.  don't give a monkey's what
	 * is sent to us, we reject it, outright
	 */

	if (l->faulted_once_before)
	{
		DEBUG(10,("rpc_redir_local: faulted before (so do it again)\n"));
		prs_free_data(&l->data_i);		
		return api_pipe_fault_resp(l, 0x1c010002, resp);
	}

	switch (l->hdr.pkt_type)
	{
		case RPC_BIND   :
		{
			reply = api_pipe_bind_req(l, name, resp);
			break;
		}
		case RPC_ALTCONT:
		{
			reply = api_pipe_alt_req(l, name, resp);
 			break;
 		}
		case RPC_REQUEST:
		{
			if (l->auth != NULL && !l->auth_validated)
			{
				/* authentication _was_ requested
				   and it failed.  sorry, no deal!
				 */
				reply = False;
			}
			else
			{
				/* read the rpc header */
				reply = smb_io_rpc_hdr_req("req", &(l->hdr_req), &l->data_i, 0);
				if (reply)
				{
					l->key.vuid = l->hdr_req.context_id;
					reply = become_vuser(&l->key) ||
					        become_guest();

				}
				if (reply)
				{	
					reply = api_pipe_request(l, name, resp);
				}
			}
			break;
		}
		case RPC_BINDRESP: /* not the real name! */
		{
			if (l->auth != NULL)
			{
				reply = l->auth->api_auth_chk(l,
				                  l->hdr.pkt_type);
			}
			if (!reply)
			{
				l->auth = NULL;
				if (l->auth_info != NULL)
				{
					free(l->auth_info);
					l->auth_info = NULL;
				}
				l->auth_validated = False;
			}
			break;
		}
	}

	if (!reply)
	{
		reply = api_pipe_fault_resp(l, 0x1c010002, resp);
	}
	
	if (reply)
	{
		/* flatten the data into a single pdu */
		DEBUG(200,("rpc_redir_local: %d\n", __LINE__));
		prs_debug_out(resp    , "redir_local resp", 200);

		return True;
	}

	/* delete intermediate data used to set up the pdu.  leave
	   rdata alone because that's got the rest of the data in it */
	prs_free_data(&l->data_i);		

	return reply;
}

/*******************************************************************
 receives a netlogon pipe and responds.
 ********************************************************************/
static BOOL api_rpc_command(rpcsrv_struct *l, const char *rpc_name,
			    const struct api_struct *api_rpc_cmds)
{
	int fn_num;
	DEBUG(4,("api_rpc_command: %s op 0x%x - ", rpc_name, l->hdr_req.opnum));

	for (fn_num = 0; api_rpc_cmds[fn_num].name; fn_num++)
	{
		if (api_rpc_cmds[fn_num].opnum == l->hdr_req.opnum && api_rpc_cmds[fn_num].fn != NULL)
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

	prs_init(&l->rdata, 0, 4, False);

	/* do the actual command */
	api_rpc_cmds[fn_num].fn(l, &l->data_i, &(l->rdata));

	if (l->rdata.data == NULL || l->rdata.offset == 0)
	{
		prs_free_data(&l->rdata);
		return False;
	}

	prs_realloc_data(&l->rdata, l->rdata.offset);

	DEBUG(10,("called %s\n", rpc_name));

	return True;
}


/*******************************************************************
 receives a netlogon pipe and responds.
 ********************************************************************/
BOOL api_rpcTNP(rpcsrv_struct *l, const char *rpc_name,
		const struct api_struct *api_rpc_cmds)
{
	if (l == NULL)
	{
		DEBUG(1, ("NULL rpcsrv_struct\n"));
		return False;
	}
	if (l->data_i.data == NULL)
	{
		DEBUG(2,("%s: NULL data received\n", rpc_name));
		return False;
	}

	/* interpret the command */
	if (!api_rpc_command(l, rpc_name, api_rpc_cmds))
	{
		return False;
	}

	return True;
}

/*******************************************************************
 entry point from msrpc to smb.  adds data received to pdu; checks
 pdu; hands pdu off to msrpc, which gets a pdu back (except in the
 case of the RPC_BINDCONT pdu).
 ********************************************************************/
BOOL rpc_local(rpcsrv_struct *l, char *data, int len, char *name)
{
	BOOL reply = False;

	DEBUG(10,("rpc_local: len %d\n", len));

	if (len != 0)
	{
		reply = prs_add_data(&l->smb_pdu, data, len);

		if (reply && is_complete_pdu(&l->smb_pdu))
		{
			l->smb_pdu.offset = l->smb_pdu.data_size;
			prs_link(NULL, &l->smb_pdu, NULL);
			reply = rpc_redir_local(l, &l->smb_pdu, &l->rsmb_pdu, name);
			prs_free_data(&l->smb_pdu);
			prs_init(&l->smb_pdu, 0, 4, True);
		}
	}
	else
	{
		if (l->rdata.data == NULL || l->rdata.data_size == 0)
		{
			DEBUG(10,("rpc_local: no data to send\n"));
			return True;
		}
		prs_free_data(&l->smb_pdu);
		prs_init(&l->smb_pdu, 0, 4, True);
		reply = rpc_redir_local(l, &l->smb_pdu, &l->rsmb_pdu, name);
	}
	return reply;
}

