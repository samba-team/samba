/* 
   Unix SMB/CIFS implementation.
   RPC pipe client
   Copyright (C) Gerald Carter                        2002,
   
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

/* implementations of client side DsXXX() functions */

/********************************************************************
 Get information about the server and directory services
********************************************************************/

NTSTATUS cli_ds_getprimarydominfo(struct cli_state *cli, TALLOC_CTX *mem_ctx, 
				  uint16 level, DS_DOMINFO_CTR *ctr)
{
	prs_struct qbuf, rbuf;
	DS_Q_GETPRIMDOMINFO q;
	DS_R_GETPRIMDOMINFO r;
	NTSTATUS result;

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Initialise parse structures */

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);
	
	q.level = level;
	
	if (!ds_io_q_getprimdominfo("", &qbuf, 0, &q) 
	    || !rpc_api_pipe_req(cli, DS_GETPRIMDOMINFO, &qbuf, &rbuf)) {
		result = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	/* Unmarshall response */

	if (!ds_io_r_getprimdominfo("", &rbuf, 0, &r)) {
		result = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}
	
	/* Return basic info - if we are requesting at info != 1 then
	   there could be trouble. */ 

	result = r.status;

	if (ctr) {
		ctr->basic = talloc(mem_ctx, sizeof(DSROLE_PRIMARY_DOMAIN_INFO_BASIC));
		if (!ctr->basic)
			goto done;
		memcpy(ctr->basic, r.info.basic, sizeof(DSROLE_PRIMARY_DOMAIN_INFO_BASIC));
	}
	
done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

	return result;
}

/********************************************************************
 Enumerate trusted domains in an AD forest
********************************************************************/

NTSTATUS cli_ds_enum_domain_trusts(struct cli_state *cli, TALLOC_CTX *mem_ctx, 
				  const char *server, uint32 flags, 
				  DS_DOMAIN_TRUSTS **trusts, uint32 *num_domains)
{
	prs_struct qbuf, rbuf;
	DS_Q_ENUM_DOM_TRUSTS q;
	DS_R_ENUM_DOM_TRUSTS r;
	NTSTATUS result;

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Initialise parse structures */

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	init_q_ds_enum_domain_trusts( &q, server, flags );
		
	if (!ds_io_q_enum_domain_trusts("", &qbuf, 0, &q) 
	    || !rpc_api_pipe_req(cli, DS_ENUM_DOM_TRUSTS, &qbuf, &rbuf)) {
		result = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	/* Unmarshall response */

	if (!ds_io_r_enum_domain_trusts("", &rbuf, 0, &r)) {
		result = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}
	
	result = r.status;
	
	if ( NT_STATUS_IS_OK(result) ) {
		int i;
	
		*num_domains = r.num_domains;
		*trusts = (DS_DOMAIN_TRUSTS*)smb_xmalloc(r.num_domains*sizeof(DS_DOMAIN_TRUSTS));
		
		memcpy( *trusts, r.domains.trusts, r.num_domains*sizeof(DS_DOMAIN_TRUSTS) );
		for ( i=0; i<r.num_domains; i++ ) {
			copy_unistr2( &(*trusts)[i].netbios_domain, &r.domains.trusts[i].netbios_domain );
			copy_unistr2( &(*trusts)[i].dns_domain,     &r.domains.trusts[i].dns_domain );
		}
	}
	
done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

	return result;
}


