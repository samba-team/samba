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
#include "smb_server/smb_server.h"
#include "librpc/gen_ndr/ndr_security.h"



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


/* 
   parse NTTRANS_CREATE request
 */
static NTSTATUS nttrans_create(struct smbsrv_request *req, 
			       struct smb_nttrans *trans)
{
	union smb_open *io;
	uint16_t fname_len;
	uint32_t sd_length, ea_length;
	NTSTATUS status;
	uint8_t *params;

	if (trans->in.params.length < 54) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	/* parse the request */
	io = talloc_p(req, union smb_open);
	if (io == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	io->ntcreatex.level = RAW_OPEN_NTTRANS_CREATE;

	params = trans->in.params.data;

	io->ntcreatex.in.flags            = IVAL(params,  0);
	io->ntcreatex.in.root_fid         = IVAL(params,  4);
	io->ntcreatex.in.access_mask      = IVAL(params,  8);
	io->ntcreatex.in.alloc_size       = BVAL(params, 12);
	io->ntcreatex.in.file_attr        = IVAL(params, 20);
	io->ntcreatex.in.share_access     = IVAL(params, 24);
	io->ntcreatex.in.open_disposition = IVAL(params, 28);
	io->ntcreatex.in.create_options   = IVAL(params, 32);
	sd_length                         = IVAL(params, 36);
	ea_length                         = IVAL(params, 40);
	fname_len                         = IVAL(params, 44);
	io->ntcreatex.in.impersonation    = IVAL(params, 48);
	io->ntcreatex.in.security_flags   = CVAL(params, 52);
	io->ntcreatex.in.sec_desc         = NULL;
	io->ntcreatex.in.ea_list          = NULL;

	req_pull_string(req, &io->ntcreatex.in.fname, 
			params + 54, 
			trans->in.params.length - 54,
			STR_NO_RANGE_CHECK | STR_TERMINATE);
	if (!io->ntcreatex.in.fname) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (sd_length > trans->in.data.length ||
	    ea_length > trans->in.data.length ||
	    (sd_length+ea_length) > trans->in.data.length) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	/* this call has an optional security descriptor */
	if (sd_length != 0) {
		DATA_BLOB blob;
		blob.data = trans->in.data.data;
		blob.length = sd_length;
		io->ntcreatex.in.sec_desc = talloc_p(io, struct security_descriptor);
		if (io->ntcreatex.in.sec_desc == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
		status = ndr_pull_struct_blob(&blob, io, 
					      io->ntcreatex.in.sec_desc, 
					      (ndr_pull_flags_fn_t)ndr_pull_security_descriptor);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
	}

	/* and an optional ea_list */
	if (ea_length > 4) {
		DATA_BLOB blob;
		blob.data = trans->in.data.data + sd_length;
		blob.length = ea_length;
		io->ntcreatex.in.ea_list = talloc_p(io, struct smb_ea_list);
		if (io->ntcreatex.in.ea_list == NULL) {
			return NT_STATUS_NO_MEMORY;
		}

		status = ea_pull_list_chained(&blob, io, 
					      &io->ntcreatex.in.ea_list->num_eas,
					      &io->ntcreatex.in.ea_list->eas);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
	}

	/* call the backend - notice that we do it sync for now, until we support
	   async nttrans requests */	
	status = ntvfs_openfile(req, io);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	trans->out.setup_count = 0;
	trans->out.setup       = NULL;
	trans->out.params      = data_blob_talloc(req, NULL, 69);
	trans->out.data        = data_blob(NULL, 0);

	params = trans->out.params.data;
	if (params == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	SSVAL(params,        0, io->ntcreatex.out.oplock_level);
	SSVAL(params,        2, io->ntcreatex.out.fnum);
	SIVAL(params,        4, io->ntcreatex.out.create_action);
	SIVAL(params,        8, 0); /* ea error offset */
	push_nttime(params, 12, io->ntcreatex.out.create_time);
	push_nttime(params, 20, io->ntcreatex.out.access_time);
	push_nttime(params, 28, io->ntcreatex.out.write_time);
	push_nttime(params, 36, io->ntcreatex.out.change_time);
	SIVAL(params,       44, io->ntcreatex.out.attrib);
	SBVAL(params,       48, io->ntcreatex.out.alloc_size);
	SBVAL(params,       56, io->ntcreatex.out.size);
	SSVAL(params,       64, io->ntcreatex.out.file_type);
	SSVAL(params,       66, io->ntcreatex.out.ipc_state);
	SCVAL(params,       68, io->ntcreatex.out.is_directory);

	return NT_STATUS_OK;
}


/* 
   parse NTTRANS_QUERY_SEC_DESC request
 */
static NTSTATUS nttrans_query_sec_desc(struct smbsrv_request *req, 
				       struct smb_nttrans *trans)
{
	union smb_fileinfo *io;
	NTSTATUS status;

	if (trans->in.params.length < 8) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	/* parse the request */
	io = talloc_p(req, union smb_fileinfo);
	if (io == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	io->query_secdesc.level            = RAW_FILEINFO_SEC_DESC;
	io->query_secdesc.in.fnum          = SVAL(trans->in.params.data, 0);
	io->query_secdesc.in.secinfo_flags = IVAL(trans->in.params.data, 4);

	/* call the backend - notice that we do it sync for now, until we support
	   async nttrans requests */	
	status = ntvfs_qfileinfo(req, io);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	trans->out.setup_count = 0;
	trans->out.setup       = NULL;
	trans->out.params      = data_blob_talloc(req, NULL, 4);
	trans->out.data        = data_blob(NULL, 0);

	status = ndr_push_struct_blob(&trans->out.data, req, 
				      io->query_secdesc.out.sd, 
				      (ndr_push_flags_fn_t)ndr_push_security_descriptor);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	SIVAL(trans->out.params.data, 0, trans->out.data.length);

	return NT_STATUS_OK;
}


/* 
   parse NTTRANS_SET_SEC_DESC request
 */
static NTSTATUS nttrans_set_sec_desc(struct smbsrv_request *req, 
				       struct smb_nttrans *trans)
{
	union smb_setfileinfo *io;
	NTSTATUS status;

	if (trans->in.params.length < 8) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	/* parse the request */
	io = talloc_p(req, union smb_setfileinfo);
	if (io == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	io->set_secdesc.level            = RAW_SFILEINFO_SEC_DESC;
	io->set_secdesc.file.fnum        = SVAL(trans->in.params.data, 0);
	io->set_secdesc.in.secinfo_flags = IVAL(trans->in.params.data, 4);

	io->set_secdesc.in.sd = talloc_p(io, struct security_descriptor);
	if (io->set_secdesc.in.sd == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	status = ndr_pull_struct_blob(&trans->in.data, req, 
				      io->set_secdesc.in.sd, 
				      (ndr_pull_flags_fn_t)ndr_pull_security_descriptor);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	/* call the backend - notice that we do it sync for now, until we support
	   async nttrans requests */	
	status = ntvfs_setfileinfo(req, io);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	trans->out.setup_count = 0;
	trans->out.setup       = NULL;
	trans->out.params      = data_blob(NULL, 0);
	trans->out.data        = data_blob(NULL, 0);

	return NT_STATUS_OK;
}


/* parse NTTRANS_RENAME request
 */
static NTSTATUS nttrans_rename(struct smbsrv_request *req, 
			       struct smb_nttrans *trans)
{
	return NT_STATUS_FOOBAR;
}

/* 
   parse NTTRANS_IOCTL request
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
	/* the nttrans command is in function */
	switch (trans->in.function) {
	case NT_TRANSACT_CREATE:
		return nttrans_create(req, trans);
	case NT_TRANSACT_IOCTL:
		return nttrans_ioctl(req, trans);
	case NT_TRANSACT_RENAME:
		return nttrans_rename(req, trans);
	case NT_TRANSACT_QUERY_SECURITY_DESC:
		return nttrans_query_sec_desc(req, trans);
	case NT_TRANSACT_SET_SECURITY_DESC:
		return nttrans_set_sec_desc(req, trans);
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

#if 0
	/* w2k3 does not check the max_setup count */
	if (trans.out.setup_count > trans.in.max_setup) {
		req_reply_error(req, NT_STATUS_BUFFER_TOO_SMALL);
		return;
	}
#endif
	if (trans.out.params.length > trans.in.max_param) {
		status = NT_STATUS_BUFFER_TOO_SMALL;
		trans.out.params.length = trans.in.max_param;
	}
	if (trans.out.data.length > trans.in.max_data) {
		status = NT_STATUS_BUFFER_TOO_SMALL;
		trans.out.data.length = trans.in.max_data;
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
