/* 
   Unix SMB/CIFS implementation.
   NT transaction handling
   Copyright (C) Andrew Tridgell 2003
   Copyright (C) James J Myers 2003 <myersjj@samba.org>

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
/*
   This file handles the parsing of transact2 requests
*/

#include "includes.h"


#define CHECK_MIN_BLOB_SIZE(blob, size) do { \
	if ((blob)->length < (size)) { \
		return NT_STATUS_INFO_LENGTH_MISMATCH; \
	}} while (0)


/* setup a nttrans reply, given the data and params sizes */
static void nttrans_setup_reply(struct smbsrv_request *req, 
			       struct smb_nttrans *trans,
			       uint16_t param_size, uint16_t data_size,
			       uint16_t setup_count)
{
	trans->out.setup_count = setup_count;
	if (setup_count != 0) {
		trans->out.setup = talloc_zero_array_p(req, uint16_t, setup_count);
	}
	trans->out.params = data_blob_talloc(req, NULL, param_size);
	trans->out.data = data_blob_talloc(req, NULL, data_size);
}


/* parse NTTRANS_CREATE request
 */
static NTSTATUS nttrans_create(struct smbsrv_request *req, 
		struct smb_nttrans *trans)
{
	return NT_STATUS_FOOBAR;
}

/* parse NTTRANS_RENAME request
 */
static NTSTATUS nttrans_rename(struct smbsrv_request *req, 
		struct smb_nttrans *trans)
{
	return NT_STATUS_FOOBAR;
}
/* parse NTTRANS_IOCTL request
 */
static NTSTATUS nttrans_ioctl(struct smbsrv_request *req, 
		struct smb_nttrans *trans)
{
	union smb_ioctl nt;
	uint32_t function;
	uint16_t fnum;
	uint8_t filter;
	BOOL fsctl;
	DATA_BLOB *blob;

	/* should have at least 4 setup words */
	if (trans->in.setup_count != 4) {
		return NT_STATUS_INVALID_PARAMETER;
	}
	
	function  = IVAL(trans->in.setup, 0);
	fnum  = SVAL(trans->in.setup, 4);
	fsctl = CVAL(trans->in.setup, 6);
	filter = CVAL(trans->in.setup, 7);

	blob = &trans->in.data;

	nt.ntioctl.level = RAW_IOCTL_NTIOCTL;
	nt.ntioctl.in.fnum = fnum;
	nt.ntioctl.in.function = function;
	nt.ntioctl.in.fsctl = fsctl;
	nt.ntioctl.in.filter = filter;

	nttrans_setup_reply(req, trans, 0, 0, 1);
	trans->out.setup[0] = 0;
	
	return ntvfs_ioctl(req, &nt);
}

/*
  backend for nttrans requests
*/
static NTSTATUS nttrans_backend(struct smbsrv_request *req, 
		struct smb_nttrans *trans)
{
	DEBUG(9,("nttrans_backend: setup_count=%d function=%d\n",
		trans->in.setup_count, trans->in.function));
	/* must have at least one setup word */
	if (trans->in.setup_count < 1) {
		return NT_STATUS_FOOBAR;
	}
	
	/* the nttrans command is in function */
	switch (trans->in.function) {
	case NT_TRANSACT_CREATE:
		return nttrans_create(req, trans);
	case NT_TRANSACT_IOCTL:
		return nttrans_ioctl(req, trans);
	case NT_TRANSACT_RENAME:
		return nttrans_rename(req, trans);
	}

	/* an unknown nttrans command */
	return NT_STATUS_FOOBAR;
}


/****************************************************************************
 Reply to an SMBnttrans request
****************************************************************************/
void reply_nttrans(struct smbsrv_request *req)
{
	struct smb_nttrans trans;
	int i;
	uint16_t param_ofs, data_ofs;
	uint16_t param_count, data_count;
	uint16_t params_left, data_left;
	uint16_t param_total, data_total;
	char *params, *data;
	NTSTATUS status;

	/* parse request */
	if (req->in.wct < 19) {
		req_reply_error(req, NT_STATUS_FOOBAR);
		return;
	}

	trans.in.max_setup   = CVAL(req->in.vwv, 0);
	param_total          = IVAL(req->in.vwv, 3);
	data_total           = IVAL(req->in.vwv, 7);
	trans.in.max_param   = IVAL(req->in.vwv, 11);
	trans.in.max_data    = IVAL(req->in.vwv, 15);
	param_count          = IVAL(req->in.vwv, 19);
	param_ofs            = IVAL(req->in.vwv, 23);
	data_count           = IVAL(req->in.vwv, 27);
	data_ofs             = IVAL(req->in.vwv, 31);
	trans.in.setup_count = CVAL(req->in.vwv, 35);
	trans.in.function	 = SVAL(req->in.vwv, 36);

	if (req->in.wct != 19 + trans.in.setup_count) {
		req_reply_dos_error(req, ERRSRV, ERRerror);
		return;
	}

	/* parse out the setup words */
	trans.in.setup = talloc(req, trans.in.setup_count * sizeof(uint16_t));
	if (!trans.in.setup) {
		req_reply_error(req, NT_STATUS_NO_MEMORY);
		return;
	}
	for (i=0;i<trans.in.setup_count;i++) {
		trans.in.setup[i] = SVAL(req->in.vwv, VWV(19+i));
	}

	if (!req_pull_blob(req, req->in.hdr + param_ofs, param_count, &trans.in.params) ||
	    !req_pull_blob(req, req->in.hdr + data_ofs, data_count, &trans.in.data)) {
		req_reply_error(req, NT_STATUS_FOOBAR);
		return;
	}

	/* is it a partial request? if so, then send a 'send more' message */
	if (param_total > param_count ||
	    data_total > data_count) {
		DEBUG(0,("REWRITE: not handling partial nttrans requests!\n"));
		return;
	}

	/* its a full request, give it to the backend */
	status = nttrans_backend(req, &trans);

	if (NT_STATUS_IS_ERR(status)) {
		req_reply_error(req, status);
		return;
	}

	params_left = trans.out.params.length;
	data_left   = trans.out.data.length;
	params      = trans.out.params.data;
	data        = trans.out.data.data;

	req_setup_reply(req, 18 + trans.out.setup_count, 0);

	if (!NT_STATUS_IS_OK(status)) {
		req_setup_error(req, status);
	}

	/* we need to divide up the reply into chunks that fit into
	   the negotiated buffer size */
	do {
		uint16_t this_data, this_param, max_bytes;
		uint_t align1 = 1, align2 = (params_left ? 2 : 0);
		struct smbsrv_request *this_req;

		max_bytes = req_max_data(req) - (align1 + align2);

		this_param = params_left;
		if (this_param > max_bytes) {
			this_param = max_bytes;
		}
		max_bytes -= this_param;

		this_data = data_left;
		if (this_data > max_bytes) {
			this_data = max_bytes;
		}

		/* don't destroy unless this is the last chunk */
		if (params_left - this_param != 0 || 
		    data_left - this_data != 0) {
			this_req = req_setup_secondary(req);
		} else {
			this_req = req;
		}

		req_grow_data(req, this_param + this_data + (align1 + align2));

		SSVAL(this_req->out.vwv, 0, 0); /* reserved */
		SCVAL(this_req->out.vwv, 2, 0); /* reserved */
		SIVAL(this_req->out.vwv, 3, trans.out.params.length);
		SIVAL(this_req->out.vwv, 7, trans.out.data.length);

		SIVAL(this_req->out.vwv, 11, this_param);
		SIVAL(this_req->out.vwv, 15, align1 + PTR_DIFF(this_req->out.data, this_req->out.hdr));
		SIVAL(this_req->out.vwv, 19, PTR_DIFF(params, trans.out.params.data));

		SIVAL(this_req->out.vwv, 23, this_data);
		SIVAL(this_req->out.vwv, 27, align1 + align2 + 
		      PTR_DIFF(this_req->out.data + this_param, this_req->out.hdr));
		SIVAL(this_req->out.vwv, 31, PTR_DIFF(data, trans.out.data.data));

		SCVAL(this_req->out.vwv, 35, trans.out.setup_count);
		for (i=0;i<trans.out.setup_count;i++) {
			SSVAL(this_req->out.vwv, VWV(18+i), trans.out.setup[i]);
		}

		memset(this_req->out.data, 0, align1);
		if (this_param != 0) {
			memcpy(this_req->out.data + align1, params, this_param);
		}
		memset(this_req->out.data+this_param+align1, 0, align2);
		if (this_data != 0) {
			memcpy(this_req->out.data+this_param+align1+align2, 
			       data, this_data);
		}

		params_left -= this_param;
		data_left -= this_data;
		params += this_param;
		data += this_data;

		req_send_reply(this_req);
	} while (params_left != 0 || data_left != 0);
}


/****************************************************************************
 Reply to an SMBnttranss request
****************************************************************************/
void reply_nttranss(struct smbsrv_request *req)
{
	req_reply_error(req, NT_STATUS_FOOBAR);
}
