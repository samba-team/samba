
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
#include "rpc_parse.h"

extern int DEBUGLEVEL;
extern struct pipe_id_info pipe_names[];
extern pstring global_myname;

/****************************************************************************
 send a request on an rpc pipe.
 ****************************************************************************/
static BOOL create_noauth_pdu(struct cli_connection *con,
				uint8 op_num,
				prs_struct *data, int data_start, int *data_end,
				prs_struct *dataa,
				uint8 *flags)
{
	/* fudge this, at the moment: create the header; memcpy the data.  oops. */
	prs_struct data_t;
	prs_struct hdr;
	int data_len;
	int frag_len;
	char *d = prs_data(data, data_start);
	struct ntdom_info *nt = cli_conn_get_ntinfo(con);

	*flags = 0;

	data_len = data->offset - data_start;

	if (data_start == 0)
	{
		(*flags) |= RPC_FLG_FIRST;
	}

	if (data_len > nt->max_recv_frag)
	{
		data_len = nt->max_recv_frag + 0x18;
	}
	else
	{
		(*flags) |= RPC_FLG_LAST;
	}

	(*data_end) += data_len;

	/* happen to know that NTLMSSP authentication verifier is 16 bytes */
	frag_len = data_len + 0x18;

	prs_init(&data_t   , 0       , 4, False);
	prs_init(&hdr      , frag_len, 4, False);

	prs_append_data(&data_t, d, data_len);
	data_t.end = data_t.data_size;
	data_t.offset = data_t.data_size;

	create_rpc_request(&hdr, nt->key.vuid, op_num, (*flags), frag_len, 0);

	prs_link(NULL, &hdr   , &data_t);
	prs_link(&hdr, &data_t, NULL   );

	DEBUG(100,("frag_len: 0x%x data_len: 0x%x data_calc_len: 0x%x\n",
		frag_len, data_len, prs_buf_len(&data_t)));

	if (frag_len != prs_buf_len(&hdr))
	{
		DEBUG(0,("expected fragment length does not match\n"));

		prs_free_data(&hdr      );
		prs_free_data(&data_t   );

		return False;
	}

	DEBUG(100,("create_noauth_pdu: %d\n", __LINE__));

	/* this is all a hack */
	prs_init(dataa, prs_buf_len(&hdr), 4, False);
	prs_debug_out(dataa, "create_noauth_pdu", 200);
	prs_buf_copy(dataa->data, &hdr, 0, frag_len);

	DEBUG(100,("create_noauth_pdu: %d\n", __LINE__));

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
static BOOL create_rpc_noauth_bind_req(struct cli_connection *con,
				prs_struct *data,
				uint32 rpc_call_id,
                                RPC_IFACE *abstract, RPC_IFACE *transfer)
{
	prs_struct rhdr;
	prs_struct rhdr_rb;

	RPC_HDR_RB           hdr_rb;
	RPC_HDR              hdr;

	DEBUG(10,("create_rpc_noauth_bind_req\n"));

	prs_init(&rhdr     , 0x0, 4, False);
	prs_init(&rhdr_rb  , 0x0, 4, False);

	/* create the bind request RPC_HDR_RB */
	make_rpc_hdr_rb(&hdr_rb, 0x1630, 0x1630, 0x0,
	                0x1, 0x0, 0x1, abstract, transfer);

	/* stream the bind request data */
	smb_io_rpc_hdr_rb("", &hdr_rb,  &rhdr_rb, 0);

	/* create the request RPC_HDR */
	make_rpc_hdr(&hdr, RPC_BIND, 0x0, rpc_call_id,
	             rhdr_rb.offset + 0x10, 0);

	smb_io_rpc_hdr("hdr"   , &hdr   , &rhdr, 0);

	if (rhdr.data == NULL || rhdr_rb.data == NULL) return False;

	/***/
	/*** link rpc header and bind acknowledgment ***/
	/***/

	prs_link(NULL , &rhdr   , &rhdr_rb);
	prs_link(&rhdr, &rhdr_rb, NULL    );

	prs_init(data, prs_buf_len(&rhdr), 4, False);
	prs_buf_copy(data->data, &rhdr, 0, prs_buf_len(&rhdr));

	prs_free_data(&rhdr     );
	prs_free_data(&rhdr_rb  );

	return True;
}

cli_auth_fns cli_noauth_fns = 
{
	create_rpc_noauth_bind_req,
	NULL,
	NULL,
	create_noauth_pdu,
	NULL
};
