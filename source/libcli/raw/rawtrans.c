/* 
   Unix SMB/CIFS implementation.
   raw trans/trans2/nttrans operations

   Copyright (C) James Myers 2003 <myersjj@samba.org>
   
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


/*
  check out of bounds for incoming data
*/
static BOOL raw_trans_oob(struct cli_request *req,
			  uint_t offset, uint_t count)
{
	char *ptr;

	if (count == 0) {
		return False;
	}

	ptr = req->in.hdr + offset;
	
	/* be careful with wraparound! */
	if (ptr < req->in.data ||
	    ptr >= req->in.data + req->in.data_size ||
	    count > req->in.data_size ||
	    ptr + count > req->in.data + req->in.data_size) {
		return True;
	}
	return False;	
}

/****************************************************************************
  receive a SMB trans or trans2 response allocating the necessary memory
  ****************************************************************************/
NTSTATUS smb_raw_trans2_recv(struct cli_request *req,
			     TALLOC_CTX *mem_ctx,
			     struct smb_trans2 *parms)
{
	int total_data=0;
	int total_param=0;
	char *tdata;
	char *tparam;

	parms->out.data.length = 0;
	parms->out.data.data = NULL;
	parms->out.params.length = 0;
	parms->out.params.data = NULL;

	if (!cli_request_receive(req)) {
		return cli_request_destroy(req);
	}
	
	/*
	 * An NT RPC pipe call can return ERRDOS, ERRmoredata
	 * to a trans call. This is not an error and should not
	 * be treated as such.
	 */
	if (NT_STATUS_IS_ERR(req->status)) {
		return cli_request_destroy(req);
	}

	CLI_CHECK_MIN_WCT(req, 10);

	/* parse out the lengths */
	total_data = SVAL(req->in.vwv, VWV(1));
	total_param = SVAL(req->in.vwv, VWV(0));

	/* allocate it */
	if (total_data != 0) {
		tdata = talloc_realloc(mem_ctx, parms->out.data.data,total_data);
		if (!tdata) {
			DEBUG(0,("smb_raw_receive_trans: failed to enlarge data buffer to %d bytes\n", total_data));
			req->status = NT_STATUS_NO_MEMORY;
			return cli_request_destroy(req);
		}
		parms->out.data.data = tdata;
	}

	if (total_param != 0) {
		tparam = talloc_realloc(mem_ctx, parms->out.params.data,total_param);
		if (!tparam) {
			DEBUG(0,("smb_raw_receive_trans: failed to enlarge param buffer to %d bytes\n", total_param));
			req->status = NT_STATUS_NO_MEMORY;
			return cli_request_destroy(req);
		}
		parms->out.params.data = tparam;
	}

	parms->out.setup_count = SVAL(req->in.vwv, VWV(9));
	CLI_CHECK_WCT(req, 10 + parms->out.setup_count);

	if (parms->out.setup_count > 0) {
		int i;
		parms->out.setup = talloc(mem_ctx, 2 * parms->out.setup_count);
		if (!parms->out.setup) {
			req->status = NT_STATUS_NO_MEMORY;
			return cli_request_destroy(req);
		}
		for (i=0;i<parms->out.setup_count;i++) {
			parms->out.setup[i] = SVAL(req->in.vwv, VWV(10+i));
		}
	}

	while (1)  {
		uint16_t param_count, param_ofs, param_disp;
		uint16_t data_count, data_ofs, data_disp;
		uint16_t total_data2, total_param2;

		/* parse out the total lengths again - they can shrink! */
		total_data2 = SVAL(req->in.vwv, VWV(1));
		total_param2 = SVAL(req->in.vwv, VWV(0));

		if (total_data2 > total_data ||
		    total_param2 > total_param) {
			/* they must *only* shrink */
			DEBUG(1,("smb_raw_receive_trans: data/params expanded!\n"));
			req->status = NT_STATUS_BUFFER_TOO_SMALL;
			return cli_request_destroy(req);
		}

		total_data = total_data2;
		total_param = total_param2;		

		/* parse params for this lump */
		param_count = SVAL(req->in.vwv, VWV(3));
		param_ofs   = SVAL(req->in.vwv, VWV(4));
		param_disp  = SVAL(req->in.vwv, VWV(5));

		data_count = SVAL(req->in.vwv, VWV(6));
		data_ofs   = SVAL(req->in.vwv, VWV(7));
		data_disp  = SVAL(req->in.vwv, VWV(8));

		if (data_count + data_disp > total_data ||
		    param_count + param_disp > total_param) {
			DEBUG(1,("smb_raw_receive_trans: Buffer overflow\n"));
			req->status = NT_STATUS_BUFFER_TOO_SMALL;
			return cli_request_destroy(req);
		}
		
		/* check the server isn't being nasty */
		if (raw_trans_oob(req, param_ofs, param_count) ||
		    raw_trans_oob(req, data_ofs, data_count)) {
			DEBUG(1,("smb_raw_receive_trans: out of bounds parameters!\n"));
			req->status = NT_STATUS_BUFFER_TOO_SMALL;
			return cli_request_destroy(req);
		}

		if (data_count) {
			memcpy(parms->out.data.data + data_disp,
			       req->in.hdr + data_ofs, 
			       data_count);
		}

		if (param_count) {
			memcpy(parms->out.params.data + param_disp,
			       req->in.hdr + param_ofs, 
			       param_count);
		}

		parms->out.data.length += data_count;
		parms->out.params.length += param_count;

		if (total_data <= parms->out.data.length && total_param <= parms->out.params.length)
			break;
	
		if (!cli_request_receive_more(req)) {
			req->status = NT_STATUS_UNSUCCESSFUL;
			return cli_request_destroy(req);
		}
	}

failed:
	return cli_request_destroy(req);
}

NTSTATUS smb_raw_trans_recv(struct cli_request *req,
			     TALLOC_CTX *mem_ctx,
			     struct smb_trans2 *parms)
{
	return smb_raw_trans2_recv(req, mem_ctx, parms);
}

/****************************************************************************
 trans/trans2 raw async interface - only BLOBs used in this interface.
 note that this doesn't yet support multi-part requests
****************************************************************************/
struct cli_request *smb_raw_trans_send_backend(struct cli_tree *tree,
					       struct smb_trans2 *parms,
					       uint8_t command)
{
	int wct = 14 + parms->in.setup_count;
	struct cli_request *req; 
	char *outdata,*outparam;
	int i;
	int padding;
	size_t namelen = 0;

	if (command == SMBtrans)
		padding = 1;
	else
		padding = 3;
	
	req = cli_request_setup(tree, command, wct, padding);
	if (!req) {
		return NULL;
	}
	
	/* fill in SMB parameters */
	outparam = req->out.data + padding;
	outdata = outparam + parms->in.params.length;

	/* make sure we don't leak data via the padding */
	memset(req->out.data, 0, padding);

	if (command == SMBtrans && parms->in.trans_name) {
		namelen = cli_req_append_string(req, parms->in.trans_name, 
						STR_TERMINATE);
	}

	/* primary request */
	SSVAL(req->out.vwv,VWV(0),parms->in.params.length);
	SSVAL(req->out.vwv,VWV(1),parms->in.data.length);
	SSVAL(req->out.vwv,VWV(2),parms->in.max_param);
	SSVAL(req->out.vwv,VWV(3),parms->in.max_data);
	SSVAL(req->out.vwv,VWV(4),parms->in.max_setup);
	SSVAL(req->out.vwv,VWV(5),parms->in.flags);
	SIVAL(req->out.vwv,VWV(6),parms->in.timeout);
	SSVAL(req->out.vwv,VWV(8),0); /* reserved */
	SSVAL(req->out.vwv,VWV(9),parms->in.params.length);
	SSVAL(req->out.vwv,VWV(10),PTR_DIFF(outparam,req->out.hdr)+namelen);
	SSVAL(req->out.vwv,VWV(11),parms->in.data.length);
	SSVAL(req->out.vwv,VWV(12),PTR_DIFF(outdata,req->out.hdr)+namelen);
	SSVAL(req->out.vwv,VWV(13),parms->in.setup_count);
	for (i=0;i<parms->in.setup_count;i++)	{
		SSVAL(req->out.vwv,VWV(14)+i*2,parms->in.setup[i]);
	}
	if (parms->in.params.data)	{
		cli_req_append_blob(req, &parms->in.params);
	}
	if (parms->in.data.data) {
		cli_req_append_blob(req, &parms->in.data);
	}

	if (!cli_request_send(req)) {
		cli_request_destroy(req);
		return NULL;
	}
	
	return req;
}

/****************************************************************************
 trans/trans2 raw async interface - only BLOBs used in this interface.
note that this doesn't yet support multi-part requests
****************************************************************************/

struct cli_request *smb_raw_trans_send(struct cli_tree *tree,
				       struct smb_trans2 *parms)
{
	return smb_raw_trans_send_backend(tree, parms, SMBtrans);
}

struct cli_request *smb_raw_trans2_send(struct cli_tree *tree,
				       struct smb_trans2 *parms)
{
	return smb_raw_trans_send_backend(tree, parms, SMBtrans2);
}

/*
  trans2 synchronous blob interface
*/
NTSTATUS smb_raw_trans2(struct cli_tree *tree,
			TALLOC_CTX *mem_ctx,
			struct smb_trans2 *parms)
{
	struct cli_request *req;
	req = smb_raw_trans2_send(tree, parms);
	if (!req) return NT_STATUS_UNSUCCESSFUL;
	return smb_raw_trans2_recv(req, mem_ctx, parms);
}


/*
  trans synchronous blob interface
*/
NTSTATUS smb_raw_trans(struct cli_tree *tree,
		       TALLOC_CTX *mem_ctx,
		       struct smb_trans2 *parms)
{
	struct cli_request *req;
	req = smb_raw_trans_send(tree, parms);
	if (!req) return NT_STATUS_UNSUCCESSFUL;
	return smb_raw_trans_recv(req, mem_ctx, parms);
}

/****************************************************************************
  receive a SMB nttrans response allocating the necessary memory
  ****************************************************************************/
NTSTATUS smb_raw_nttrans_recv(struct cli_request *req,
			      TALLOC_CTX *mem_ctx,
			      struct smb_nttrans *parms)
{
	uint32_t total_data, recvd_data=0;
	uint32_t total_param, recvd_param=0;

	if (!cli_request_receive(req) ||
	    cli_request_is_error(req)) {
		return cli_request_destroy(req);
	}

	/* sanity check */
	if (CVAL(req->in.hdr, HDR_COM) != SMBnttrans) {
		DEBUG(0,("smb_raw_receive_nttrans: Expected %s response, got command 0x%02x\n",
			 "SMBnttrans", 
			 CVAL(req->in.hdr,HDR_COM)));
		req->status = NT_STATUS_UNSUCCESSFUL;
		return cli_request_destroy(req);
	}

	CLI_CHECK_MIN_WCT(req, 18);

	/* parse out the lengths */
	total_param = IVAL(req->in.vwv, 3);
	total_data  = IVAL(req->in.vwv, 7);

	parms->out.data = data_blob_talloc(mem_ctx, NULL, total_data);
	parms->out.params = data_blob_talloc(mem_ctx, NULL, total_param);

	if (parms->out.data.length != total_data ||
	    parms->out.params.length != total_param) {
		req->status = NT_STATUS_NO_MEMORY;
		return cli_request_destroy(req);
	}

	parms->out.setup_count = CVAL(req->in.vwv, 35);
	CLI_CHECK_WCT(req, 18 + parms->out.setup_count);

	if (parms->out.setup_count > 0) {
		int i;
		parms->out.setup = talloc(mem_ctx, 2 * parms->out.setup_count);
		if (!parms->out.setup) {
			req->status = NT_STATUS_NO_MEMORY;
			return cli_request_destroy(req);
		}
		for (i=0;i<parms->out.setup_count;i++) {
			parms->out.setup[i] = SVAL(req->in.vwv, VWV(18+i));
		}
	}
	
	while (recvd_data < total_data || 
	       recvd_param < total_param)  {
		uint32_t param_count, param_ofs, param_disp;
		uint32_t data_count, data_ofs, data_disp;
		uint32_t total_data2, total_param2;

		/* parse out the total lengths again - they can shrink! */
		total_param2 = IVAL(req->in.vwv, 3);
		total_data2  = IVAL(req->in.vwv, 7);

		if (total_data2 > total_data ||
		    total_param2 > total_param) {
			/* they must *only* shrink */
			DEBUG(1,("smb_raw_receive_nttrans: data/params expanded!\n"));
			req->status = NT_STATUS_BUFFER_TOO_SMALL;
			return cli_request_destroy(req);
		}

		total_data = total_data2;
		total_param = total_param2;
		parms->out.data.length = total_data;
		parms->out.params.length = total_param;

		/* parse params for this lump */
		param_count = IVAL(req->in.vwv, 11);
		param_ofs   = IVAL(req->in.vwv, 15);
		param_disp  = IVAL(req->in.vwv, 19);

		data_count = IVAL(req->in.vwv, 23);
		data_ofs   = IVAL(req->in.vwv, 27);
		data_disp  = IVAL(req->in.vwv, 31);

		if (data_count + data_disp > total_data ||
		    param_count + param_disp > total_param) {
			DEBUG(1,("smb_raw_receive_nttrans: Buffer overflow\n"));
			req->status = NT_STATUS_BUFFER_TOO_SMALL;
			return cli_request_destroy(req);
		}
		
		/* check the server isn't being nasty */
		if (raw_trans_oob(req, param_ofs, param_count) ||
		    raw_trans_oob(req, data_ofs, data_count)) {
			DEBUG(1,("smb_raw_receive_nttrans: out of bounds parameters!\n"));
			req->status = NT_STATUS_BUFFER_TOO_SMALL;
			return cli_request_destroy(req);
		}

		if (data_count) {
			memcpy(parms->out.data.data + data_disp,
			       req->in.hdr + data_ofs, 
			       data_count);
		}

		if (param_count) {
			memcpy(parms->out.params.data + param_disp,
			       req->in.hdr + param_ofs, 
			       param_count);
		}

		recvd_param += param_count;
		recvd_data += data_count;

		if (recvd_data >= total_data &&
		    recvd_param >= total_param) {
			break;
		}
		
		if (!cli_request_receive(req) ||
		    cli_request_is_error(req)) {
			return cli_request_destroy(req);
		}
		
		/* sanity check */
		if (CVAL(req->in.hdr, HDR_COM) != SMBnttrans) {
			DEBUG(0,("smb_raw_receive_nttrans: Expected nttranss, got command 0x%02x\n",
				 CVAL(req->in.hdr, HDR_COM)));
			req->status = NT_STATUS_UNSUCCESSFUL;
			return cli_request_destroy(req);
		}
	}

failed:
	return cli_request_destroy(req);
}


/****************************************************************************
 nttrans raw - only BLOBs used in this interface.
 at the moment we only handle a single primary request 
****************************************************************************/
struct cli_request *smb_raw_nttrans_send(struct cli_tree *tree,
					 struct smb_nttrans *parms)
{
	struct cli_request *req; 
	char *outdata, *outparam;
	int i;
	int align = 0;

	/* only align if there are parameters or data */
	if (parms->in.params.length || parms->in.data.length) {
		align = 3;
	}
	
	req = cli_request_setup(tree, SMBnttrans, 
				19 + parms->in.setup_count, 
				align +
				parms->in.params.length +
				parms->in.data.length);
	if (!req) {
		return NULL;
	}
	
	/* fill in SMB parameters */
	outparam = req->out.data + align;
	outdata = outparam + parms->in.params.length;

	SCVAL(req->out.vwv,  0, parms->in.max_setup);
	SSVAL(req->out.vwv,  1, 0); /* reserved */
	SIVAL(req->out.vwv,  3, parms->in.params.length);
	SIVAL(req->out.vwv,  7, parms->in.data.length);
	SIVAL(req->out.vwv, 11, parms->in.max_param);
	SIVAL(req->out.vwv, 15, parms->in.max_data);
	SIVAL(req->out.vwv, 19, parms->in.params.length);
	SIVAL(req->out.vwv, 23, PTR_DIFF(outparam,req->out.hdr));
	SIVAL(req->out.vwv, 27, parms->in.data.length);
	SIVAL(req->out.vwv, 31, PTR_DIFF(outdata,req->out.hdr));
	SCVAL(req->out.vwv, 35, parms->in.setup_count);
	SSVAL(req->out.vwv, 36, parms->in.function);
	for (i=0;i<parms->in.setup_count;i++) {
		SSVAL(req->out.vwv,VWV(19+i),parms->in.setup[i]);
	}
	if (parms->in.params.length) {
		memcpy(outparam, parms->in.params.data, parms->in.params.length);
	}
	if (parms->in.data.length) {
		memcpy(outparam, parms->in.data.data, parms->in.data.length);
	}

	if (!cli_request_send(req)) {
		cli_request_destroy(req);
		return NULL;
	}

	return req;
}


/****************************************************************************
  receive a SMB nttrans response allocating the necessary memory
  ****************************************************************************/
NTSTATUS smb_raw_nttrans(struct cli_tree *tree,
			 TALLOC_CTX *mem_ctx,
			 struct smb_nttrans *parms)
{
	struct cli_request *req;

	req = smb_raw_nttrans_send(tree, parms);
	if (!req) {
		return NT_STATUS_UNSUCCESSFUL;
	}

	return smb_raw_nttrans_recv(req, mem_ctx, parms);
}
