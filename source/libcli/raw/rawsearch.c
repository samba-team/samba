/* 
   Unix SMB/CIFS implementation.
   client directory search routines
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

/****************************************************************************
 Old style search backend - process output.
****************************************************************************/
static void smb_raw_search_backend(struct smbcli_request *req,
				   TALLOC_CTX *mem_ctx,
				   uint16_t count, 
				   void *private,
				   BOOL (*callback)(void *private, union smb_search_data *file))

{
	union smb_search_data search_data;
	int i;
	char *p;

	if (req->in.data_size < 3 + count*43) {
		req->status = NT_STATUS_INVALID_PARAMETER;
		return;
	}
	
	p = req->in.data + 3;

	for (i=0; i < count; i++) {
		char *name;

		search_data.search.id.reserved      = CVAL(p, 0);
		memcpy(search_data.search.id.name,    p+1, 11);
		search_data.search.id.handle        = CVAL(p, 12);
		search_data.search.id.server_cookie = IVAL(p, 13);
		search_data.search.id.client_cookie = IVAL(p, 17);
		search_data.search.attrib           = CVAL(p, 21);
		search_data.search.write_time       = raw_pull_dos_date(req->transport,
									p + 22);
		search_data.search.size             = IVAL(p, 26);
		smbcli_req_pull_ascii(req, mem_ctx, &name, p+30, 13, STR_ASCII);
		search_data.search.name = name;
		if (!callback(private, &search_data)) {
			break;
		}
		p += 43;
	}
}

/****************************************************************************
 Old style search first.
****************************************************************************/
static NTSTATUS smb_raw_search_first_old(struct smbcli_tree *tree,
					 TALLOC_CTX *mem_ctx,
					 union smb_search_first *io, void *private,
					 BOOL (*callback)(void *private, union smb_search_data *file))

{
	struct smbcli_request *req; 
	uint8_t op = SMBsearch;

	if (io->generic.level == RAW_SEARCH_FFIRST) {
		op = SMBffirst;
	} else if (io->generic.level == RAW_SEARCH_FUNIQUE) {
		op = SMBfunique;
	}

	req = smbcli_request_setup(tree, op, 2, 0);
	if (!req) {
		return NT_STATUS_NO_MEMORY;
	}
	
	SSVAL(req->out.vwv, VWV(0), io->search_first.in.max_count);
	SSVAL(req->out.vwv, VWV(1), io->search_first.in.search_attrib);
	smbcli_req_append_ascii4(req, io->search_first.in.pattern, STR_TERMINATE);
	smbcli_req_append_var_block(req, NULL, 0);

	if (!smbcli_request_send(req) || 
	    !smbcli_request_receive(req)) {
		return smbcli_request_destroy(req);
	}

	if (NT_STATUS_IS_OK(req->status)) {
		io->search_first.out.count = SVAL(req->in.vwv, VWV(0));	
		smb_raw_search_backend(req, mem_ctx, io->search_first.out.count, private, callback);
	}

	return smbcli_request_destroy(req);
}

/****************************************************************************
 Old style search next.
****************************************************************************/
static NTSTATUS smb_raw_search_next_old(struct smbcli_tree *tree,
					TALLOC_CTX *mem_ctx,
					union smb_search_next *io, void *private,
					BOOL (*callback)(void *private, union smb_search_data *file))

{
	struct smbcli_request *req; 
	uint8_t var_block[21];
	uint8_t op = SMBsearch;

	if (io->generic.level == RAW_SEARCH_FFIRST) {
		op = SMBffirst;
	}
	
	req = smbcli_request_setup(tree, op, 2, 0);
	if (!req) {
		return NT_STATUS_NO_MEMORY;
	}
	
	SSVAL(req->out.vwv, VWV(0), io->search_next.in.max_count);
	SSVAL(req->out.vwv, VWV(1), io->search_next.in.search_attrib);
	smbcli_req_append_ascii4(req, "", STR_TERMINATE);

	SCVAL(var_block,  0, io->search_next.in.id.reserved);
	memcpy(&var_block[1], io->search_next.in.id.name, 11);
	SCVAL(var_block, 12, io->search_next.in.id.handle);
	SIVAL(var_block, 13, io->search_next.in.id.server_cookie);
	SIVAL(var_block, 17, io->search_next.in.id.client_cookie);

	smbcli_req_append_var_block(req, var_block, 21);

	if (!smbcli_request_send(req) ||
	    !smbcli_request_receive(req)) {
		return smbcli_request_destroy(req);
	}

	if (NT_STATUS_IS_OK(req->status)) {
		io->search_next.out.count = SVAL(req->in.vwv, VWV(0));
		smb_raw_search_backend(req, mem_ctx, io->search_next.out.count, private, callback);
	}
	
	return smbcli_request_destroy(req);
}


/****************************************************************************
 Old style search next.
****************************************************************************/
static NTSTATUS smb_raw_search_close_old(struct smbcli_tree *tree,
					 union smb_search_close *io)
{
	struct smbcli_request *req; 
	uint8_t var_block[21];

	req = smbcli_request_setup(tree, SMBfclose, 2, 0);
	if (!req) {
		return NT_STATUS_NO_MEMORY;
	}
	
	SSVAL(req->out.vwv, VWV(0), io->fclose.in.max_count);
	SSVAL(req->out.vwv, VWV(1), io->fclose.in.search_attrib);
	smbcli_req_append_ascii4(req, "", STR_TERMINATE);

	SCVAL(var_block,  0, io->fclose.in.id.reserved);
	memcpy(&var_block[1], io->fclose.in.id.name, 11);
	SCVAL(var_block, 12, io->fclose.in.id.handle);
	SIVAL(var_block, 13, io->fclose.in.id.server_cookie);
	SIVAL(var_block, 17, io->fclose.in.id.client_cookie);

	smbcli_req_append_var_block(req, var_block, 21);

	if (!smbcli_request_send(req) ||
	    !smbcli_request_receive(req)) {
		return smbcli_request_destroy(req);
	}

	return smbcli_request_destroy(req);
}



/****************************************************************************
 Very raw search first - returns param/data blobs.
****************************************************************************/
static NTSTATUS smb_raw_search_first_blob(struct smbcli_tree *tree,
					  TALLOC_CTX *mem_ctx,	/* used to allocate output blobs */
					  union smb_search_first *io,
					  uint16_t info_level,
					  DATA_BLOB *out_param_blob,
					  DATA_BLOB *out_data_blob)
{
	struct smb_trans2 tp;
	uint16_t setup = TRANSACT2_FINDFIRST;
	NTSTATUS status;
	
	tp.in.max_setup = 0;
	tp.in.flags = 0; 
	tp.in.timeout = 0;
	tp.in.setup_count = 1;
	tp.in.data = data_blob(NULL, 0);
	tp.in.max_param = 10;
	tp.in.max_data = smb_raw_max_trans_data(tree, 10);
	tp.in.setup = &setup;
	
	tp.in.params = data_blob_talloc(mem_ctx, NULL, 12);
	if (!tp.in.params.data) {
		return NT_STATUS_NO_MEMORY;
	}

	SSVAL(tp.in.params.data, 0, io->t2ffirst.in.search_attrib);
	SSVAL(tp.in.params.data, 2, io->t2ffirst.in.max_count);	
	SSVAL(tp.in.params.data, 4, io->t2ffirst.in.flags);
	SSVAL(tp.in.params.data, 6, info_level);
	SIVAL(tp.in.params.data, 8, io->t2ffirst.in.storage_type);

	smbcli_blob_append_string(tree->session, mem_ctx, &tp.in.params,
			       io->t2ffirst.in.pattern, STR_TERMINATE);

	status = smb_raw_trans2(tree, mem_ctx, &tp);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	out_param_blob->length = tp.out.params.length;
	out_param_blob->data = tp.out.params.data;
	out_data_blob->length = tp.out.data.length;
	out_data_blob->data = tp.out.data.data;

	return NT_STATUS_OK;
}


/****************************************************************************
 Very raw search first - returns param/data blobs.
 Used in CIFS-on-CIFS NTVFS.
****************************************************************************/
static NTSTATUS smb_raw_search_next_blob(struct smbcli_tree *tree,
					 TALLOC_CTX *mem_ctx,
					 union smb_search_next *io,
					 uint16_t info_level,
					 DATA_BLOB *out_param_blob,
					 DATA_BLOB *out_data_blob)
{
	struct smb_trans2 tp;
	uint16_t setup = TRANSACT2_FINDNEXT;
	NTSTATUS status;
	
	tp.in.max_setup = 0;
	tp.in.flags = 0; 
	tp.in.timeout = 0;
	tp.in.setup_count = 1;
	tp.in.data = data_blob(NULL, 0);
	tp.in.max_param = 10;
	tp.in.max_data = smb_raw_max_trans_data(tree, 10);
	tp.in.setup = &setup;
	
	tp.in.params = data_blob_talloc(mem_ctx, NULL, 12);
	if (!tp.in.params.data) {
		return NT_STATUS_NO_MEMORY;
	}
	
	SSVAL(tp.in.params.data, 0, io->t2fnext.in.handle);
	SSVAL(tp.in.params.data, 2, io->t2fnext.in.max_count);	
	SSVAL(tp.in.params.data, 4, info_level);
	SIVAL(tp.in.params.data, 6, io->t2fnext.in.resume_key);
	SSVAL(tp.in.params.data, 10, io->t2fnext.in.flags);

	smbcli_blob_append_string(tree->session, mem_ctx, &tp.in.params,
			       io->t2fnext.in.last_name,
			       STR_TERMINATE);

	status = smb_raw_trans2(tree, mem_ctx, &tp);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	out_param_blob->length = tp.out.params.length;
	out_param_blob->data = tp.out.params.data;
	out_data_blob->length = tp.out.data.length;
	out_data_blob->data = tp.out.data.data;

	return NT_STATUS_OK;
}


/*
  parse a trans2 search response. 
  Return the number of bytes consumed
  return 0 for success with end of list
  return -1 for a parse error
*/
static int parse_trans2_search(struct smbcli_tree *tree,
			       TALLOC_CTX *mem_ctx, 
			       enum smb_search_level level,
			       uint16_t flags,
			       DATA_BLOB *blob,
			       union smb_search_data *data)
{
	uint_t len, ofs;

	switch (level) {
	case RAW_SEARCH_GENERIC:
	case RAW_SEARCH_SEARCH:
	case RAW_SEARCH_FFIRST:
	case RAW_SEARCH_FUNIQUE:
		/* handled elsewhere */
		return -1;

	case RAW_SEARCH_STANDARD:
		if (flags & FLAG_TRANS2_FIND_REQUIRE_RESUME) {
			if (blob->length < 4) return -1;
			data->standard.resume_key = IVAL(blob->data, 0);
			blob->data += 4;
			blob->length -= 4;
		}
		if (blob->length < 24) return -1;
		data->standard.create_time = raw_pull_dos_date2(tree->session->transport,
								blob->data + 0);
		data->standard.access_time = raw_pull_dos_date2(tree->session->transport,
								blob->data + 4);
		data->standard.write_time  = raw_pull_dos_date2(tree->session->transport,
								blob->data + 8);
		data->standard.size        = IVAL(blob->data, 12);
		data->standard.alloc_size  = IVAL(blob->data, 16);
		data->standard.attrib      = SVAL(blob->data, 20);
		len = smbcli_blob_pull_string(tree->session, mem_ctx, blob,
					   &data->standard.name,
					   22, 23, STR_LEN8BIT | STR_TERMINATE | STR_LEN_NOTERM);
		return len + 23;

	case RAW_SEARCH_EA_SIZE:
		if (flags & FLAG_TRANS2_FIND_REQUIRE_RESUME) {
			if (blob->length < 4) return -1;
			data->ea_size.resume_key = IVAL(blob->data, 0);
			blob->data += 4;
			blob->length -= 4;
		}
		if (blob->length < 28) return -1;
		data->ea_size.create_time = raw_pull_dos_date2(tree->session->transport,
							       blob->data + 0);
		data->ea_size.access_time = raw_pull_dos_date2(tree->session->transport,
							       blob->data + 4);
		data->ea_size.write_time  = raw_pull_dos_date2(tree->session->transport,
							       blob->data + 8);
		data->ea_size.size        = IVAL(blob->data, 12);
		data->ea_size.alloc_size  = IVAL(blob->data, 16);
		data->ea_size.attrib      = SVAL(blob->data, 20);
		data->ea_size.ea_size     = IVAL(blob->data, 22);
		len = smbcli_blob_pull_string(tree->session, mem_ctx, blob,
					   &data->ea_size.name,
					   26, 27, STR_LEN8BIT | STR_TERMINATE | STR_NOALIGN);
		return len + 27 + 1;

	case RAW_SEARCH_DIRECTORY_INFO:
		if (blob->length < 65) return -1;
		ofs                                     = IVAL(blob->data,             0);
		data->directory_info.file_index  = IVAL(blob->data,             4);
		data->directory_info.create_time = smbcli_pull_nttime(blob->data,  8);
		data->directory_info.access_time = smbcli_pull_nttime(blob->data, 16);
		data->directory_info.write_time  = smbcli_pull_nttime(blob->data, 24);
		data->directory_info.change_time = smbcli_pull_nttime(blob->data, 32);
		data->directory_info.size        = BVAL(blob->data,            40);
		data->directory_info.alloc_size  = BVAL(blob->data,            48);
		data->directory_info.attrib      = IVAL(blob->data,            56);
		len = smbcli_blob_pull_string(tree->session, mem_ctx, blob,
					   &data->directory_info.name,
					   60, 64, 0);
		if (ofs != 0 && ofs < 64+len) {
			return -1;
		}
		return ofs;

	case RAW_SEARCH_FULL_DIRECTORY_INFO:
		if (blob->length < 69) return -1;
		ofs                                   = IVAL(blob->data,             0);
		data->full_directory_info.file_index  = IVAL(blob->data,             4);
		data->full_directory_info.create_time = smbcli_pull_nttime(blob->data,  8);
		data->full_directory_info.access_time = smbcli_pull_nttime(blob->data, 16);
		data->full_directory_info.write_time  = smbcli_pull_nttime(blob->data, 24);
		data->full_directory_info.change_time = smbcli_pull_nttime(blob->data, 32);
		data->full_directory_info.size        = BVAL(blob->data,            40);
		data->full_directory_info.alloc_size  = BVAL(blob->data,            48);
		data->full_directory_info.attrib      = IVAL(blob->data,            56);
		data->full_directory_info.ea_size     = IVAL(blob->data,            64);
		len = smbcli_blob_pull_string(tree->session, mem_ctx, blob,
					   &data->full_directory_info.name,
					   60, 68, 0);
		if (ofs != 0 && ofs < 68+len) {
			return -1;
		}
		return ofs;

	case RAW_SEARCH_NAME_INFO:
		if (blob->length < 13) return -1;
		ofs                         = IVAL(blob->data,             0);
		data->name_info.file_index  = IVAL(blob->data,             4);
		len = smbcli_blob_pull_string(tree->session, mem_ctx, blob,
					   &data->name_info.name,
					   8, 12, 0);
		if (ofs != 0 && ofs < 12+len) {
			return -1;
		}
		return ofs;


	case RAW_SEARCH_BOTH_DIRECTORY_INFO:
		if (blob->length < 95) return -1;
		ofs                                          = IVAL(blob->data,             0);
		data->both_directory_info.file_index  = IVAL(blob->data,             4);
		data->both_directory_info.create_time = smbcli_pull_nttime(blob->data,  8);
		data->both_directory_info.access_time = smbcli_pull_nttime(blob->data, 16);
		data->both_directory_info.write_time  = smbcli_pull_nttime(blob->data, 24);
		data->both_directory_info.change_time = smbcli_pull_nttime(blob->data, 32);
		data->both_directory_info.size        = BVAL(blob->data,            40);
		data->both_directory_info.alloc_size  = BVAL(blob->data,            48);
		data->both_directory_info.attrib      = IVAL(blob->data,            56);
		data->both_directory_info.ea_size     = IVAL(blob->data,            64);
		smbcli_blob_pull_string(tree->session, mem_ctx, blob,
				     &data->both_directory_info.short_name,
				     68, 70, STR_LEN8BIT | STR_UNICODE);
		len = smbcli_blob_pull_string(tree->session, mem_ctx, blob,
					   &data->both_directory_info.name,
					   60, 94, 0);
		if (ofs != 0 && ofs < 94+len) {
			return -1;
		}
		return ofs;


	case RAW_SEARCH_ID_FULL_DIRECTORY_INFO:
		if (blob->length < 81) return -1;
		ofs                                      = IVAL(blob->data,             0);
		data->id_full_directory_info.file_index  = IVAL(blob->data,             4);
		data->id_full_directory_info.create_time = smbcli_pull_nttime(blob->data,  8);
		data->id_full_directory_info.access_time = smbcli_pull_nttime(blob->data, 16);
		data->id_full_directory_info.write_time  = smbcli_pull_nttime(blob->data, 24);
		data->id_full_directory_info.change_time = smbcli_pull_nttime(blob->data, 32);
		data->id_full_directory_info.size        = BVAL(blob->data,            40);
		data->id_full_directory_info.alloc_size  = BVAL(blob->data,            48);
		data->id_full_directory_info.attrib      = IVAL(blob->data,            56);
		data->id_full_directory_info.ea_size     = IVAL(blob->data,            64);
		data->id_full_directory_info.file_id     = BVAL(blob->data,            72);
		len = smbcli_blob_pull_string(tree->session, mem_ctx, blob,
					   &data->id_full_directory_info.name,
					   60, 80, 0);
		if (ofs != 0 && ofs < 80+len) {
			return -1;
		}
		return ofs;

	case RAW_SEARCH_ID_BOTH_DIRECTORY_INFO:
		if (blob->length < 105) return -1;
		ofs                                      = IVAL(blob->data,             0);
		data->id_both_directory_info.file_index  = IVAL(blob->data,             4);
		data->id_both_directory_info.create_time = smbcli_pull_nttime(blob->data,  8);
		data->id_both_directory_info.access_time = smbcli_pull_nttime(blob->data, 16);
		data->id_both_directory_info.write_time  = smbcli_pull_nttime(blob->data, 24);
		data->id_both_directory_info.change_time = smbcli_pull_nttime(blob->data, 32);
		data->id_both_directory_info.size        = BVAL(blob->data,            40);
		data->id_both_directory_info.alloc_size  = BVAL(blob->data,            48);
		data->id_both_directory_info.attrib      = SVAL(blob->data,            56);
		data->id_both_directory_info.ea_size     = IVAL(blob->data,            64);
		smbcli_blob_pull_string(tree->session, mem_ctx, blob,
				     &data->id_both_directory_info.short_name,
				     68, 70, STR_LEN8BIT | STR_UNICODE);
		data->id_both_directory_info.file_id     = BVAL(blob->data,            96);
		len = smbcli_blob_pull_string(tree->session, mem_ctx, blob,
					   &data->id_both_directory_info.name,
					   60, 104, 0);
		if (ofs != 0 && ofs < 104+len) {
			return -1;
		}
		return ofs;
	
	case RAW_SEARCH_UNIX_INFO:
		if (blob->length < 109) return -1;
		ofs                                  = IVAL(blob->data,             0);
		data->unix_info.file_index           = IVAL(blob->data,             4);
		data->unix_info.size                 = BVAL(blob->data,             8);
		data->unix_info.alloc_size           = BVAL(blob->data,            16);
		data->unix_info.status_change_time   = smbcli_pull_nttime(blob->data, 24);
		data->unix_info.access_time          = smbcli_pull_nttime(blob->data, 32);
		data->unix_info.change_time          = smbcli_pull_nttime(blob->data, 40);
		data->unix_info.uid                  = IVAL(blob->data,            48);
		data->unix_info.gid                  = IVAL(blob->data,            56);
		data->unix_info.file_type            = IVAL(blob->data,            64);
		data->unix_info.dev_major            = BVAL(blob->data,            68);
		data->unix_info.dev_minor            = BVAL(blob->data,            76);
		data->unix_info.unique_id            = BVAL(blob->data,            84);
		data->unix_info.permissions          = IVAL(blob->data,            92);
		data->unix_info.nlink                = IVAL(blob->data,           100);
		/* There is no length field for this name but we know it's null terminated. */
		len = smbcli_blob_pull_unix_string(tree->session, mem_ctx, blob,
					   &data->unix_info.name, 108, 0);
		if (ofs != 0 && ofs < 108+len) {
			return -1;
		}
		return ofs;

	}
	/* invalid level */
	return -1;
}

/****************************************************************************
 Trans2 search backend - process output.
****************************************************************************/
static NTSTATUS smb_raw_t2search_backend(struct smbcli_tree *tree,
					 TALLOC_CTX *mem_ctx,
					 enum smb_search_level level,
					 uint16_t flags,
					 int16_t count,
					 DATA_BLOB *blob,
					 void *private,
					 BOOL (*callback)(void *private, union smb_search_data *file))

{
	int i;
	DATA_BLOB blob2;

	blob2.data = blob->data;
	blob2.length = blob->length;

	for (i=0; i < count; i++) {
		union smb_search_data search_data;
		uint_t len;

		len = parse_trans2_search(tree, mem_ctx, level, flags, &blob2, &search_data);
		if (len == -1) {
			return NT_STATUS_INVALID_PARAMETER;
		}

		/* the callback function can tell us that no more will
		   fit - in that case we stop, but it isn't an error */
		if (!callback(private, &search_data)) {
			break;
		}

		if (len == 0) break;

		blob2.data += len;
		blob2.length -= len;
	}

	return NT_STATUS_OK;
}


/* Implements trans2findfirst2 and old search
 */
NTSTATUS smb_raw_search_first(struct smbcli_tree *tree,
			      TALLOC_CTX *mem_ctx,
			      union smb_search_first *io, void *private,
			      BOOL (*callback)(void *private, union smb_search_data *file))
{
	uint16_t info_level = 0;
	DATA_BLOB p_blob, d_blob;
	NTSTATUS status;
			
	if (io->generic.level == RAW_SEARCH_SEARCH ||
	    io->generic.level == RAW_SEARCH_FFIRST ||
	    io->generic.level == RAW_SEARCH_FUNIQUE) {
		return smb_raw_search_first_old(tree, mem_ctx, io, private, callback);
	}
	if (io->generic.level >= RAW_SEARCH_GENERIC) {
		return NT_STATUS_INVALID_LEVEL;
	}
	info_level = (uint16_t)io->generic.level;

	status = smb_raw_search_first_blob(tree, mem_ctx,
					   io, info_level, &p_blob, &d_blob);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	
	if (p_blob.length < 10) {
		DEBUG(1,("smb_raw_search_first: parms wrong size %d != expected_param_size\n",
			p_blob.length));
		return NT_STATUS_INVALID_PARAMETER;
	}

	/* process output data */
	io->t2ffirst.out.handle = SVAL(p_blob.data, 0);
	io->t2ffirst.out.count = SVAL(p_blob.data, 2);
	io->t2ffirst.out.end_of_search = SVAL(p_blob.data, 4);
		
	status = smb_raw_t2search_backend(tree, mem_ctx,
					  io->generic.level, 
					  io->t2ffirst.in.flags, io->t2ffirst.out.count,
					  &d_blob, private, callback);
	
	return status;
}

/* Implements trans2findnext2 and old smbsearch
 */
NTSTATUS smb_raw_search_next(struct smbcli_tree *tree,
			     TALLOC_CTX *mem_ctx,
			     union smb_search_next *io, void *private,
			     BOOL (*callback)(void *private, union smb_search_data *file))
{
	uint16_t info_level = 0;
	DATA_BLOB p_blob, d_blob;
	NTSTATUS status;

	if (io->generic.level == RAW_SEARCH_SEARCH ||
	    io->generic.level == RAW_SEARCH_FFIRST) {
		return smb_raw_search_next_old(tree, mem_ctx, io, private, callback);
	}
	if (io->generic.level >= RAW_SEARCH_GENERIC) {
		return NT_STATUS_INVALID_LEVEL;
	}
	info_level = (uint16_t)io->generic.level;

	status = smb_raw_search_next_blob(tree, mem_ctx,
					  io, info_level, &p_blob, &d_blob);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	
	if (p_blob.length != 8) {
		DEBUG(1,("smb_raw_search_next: parms wrong size %d != expected_param_size\n",
			p_blob.length));
		return NT_STATUS_INVALID_PARAMETER;
	}

	/* process output data */
	io->t2fnext.out.count = SVAL(p_blob.data, 0);
	io->t2fnext.out.end_of_search = SVAL(p_blob.data, 2);
		
	status = smb_raw_t2search_backend(tree, mem_ctx,
					  io->generic.level, 
					  io->t2fnext.in.flags, io->t2fnext.out.count,
					  &d_blob, private, callback);
	
	return status;
}

/* 
   Implements trans2findclose2
 */
NTSTATUS smb_raw_search_close(struct smbcli_tree *tree,
			      union smb_search_close *io)
{
	struct smbcli_request *req;

	if (io->generic.level == RAW_FINDCLOSE_FCLOSE) {
		return smb_raw_search_close_old(tree, io);
	}
	
	req = smbcli_request_setup(tree, SMBfindclose, 1, 0);
	if (!req) {
		return NT_STATUS_NO_MEMORY;
	}

	SSVAL(req->out.vwv, VWV(0), io->findclose.in.handle);

	if (smbcli_request_send(req)) {
		smbcli_request_receive(req);
	}

	return smbcli_request_destroy(req);
}
