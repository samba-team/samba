/* 
   Unix SMB/CIFS implementation.
   transaction2 handling
   Copyright (C) Andrew Tridgell 2003

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

/* grow the data allocation size of a trans2 reply - this guarantees
   that requests to grow the data size later will not change the
   pointer */
static void trans2_grow_data_allocation(struct smbsrv_request *req, 
					struct smb_trans2 *trans,
					uint16_t new_size)
{
	if (new_size <= trans->out.data.length) {
		return;
	}
	trans->out.data.data = talloc_realloc(trans->out.data.data, new_size);
}


/* grow the data size of a trans2 reply */
static void trans2_grow_data(struct smbsrv_request *req, 
			     struct smb_trans2 *trans,
			     uint16_t new_size)
{
	trans2_grow_data_allocation(req, trans, new_size);
	trans->out.data.length = new_size;
}

/* grow the data, zero filling any new bytes */
static void trans2_grow_data_fill(struct smbsrv_request *req, 
				  struct smb_trans2 *trans,
				  uint16_t new_size)
{
	uint16_t old_size = trans->out.data.length;
	trans2_grow_data(req, trans, new_size);
	if (new_size > old_size) {
		memset(trans->out.data.data + old_size, 0, new_size - old_size);
	}
}


/* setup a trans2 reply, given the data and params sizes */
static void trans2_setup_reply(struct smbsrv_request *req, 
			       struct smb_trans2 *trans,
			       uint16_t param_size, uint16_t data_size,
			       uint16_t setup_count)
{
	trans->out.setup_count = setup_count;
	if (setup_count != 0) {
		trans->out.setup = talloc_zero(req, sizeof(uint16_t) * setup_count);
	}
	trans->out.params = data_blob_talloc(req, NULL, param_size);
	trans->out.data = data_blob_talloc(req, NULL, data_size);
}


/*
  pull a string from a blob in a trans2 request
*/
static size_t trans2_pull_blob_string(struct smbsrv_request *req, 
				      const DATA_BLOB *blob,
				      uint16_t offset,
				      const char **str,
				      int flags)
{
	/* we use STR_NO_RANGE_CHECK because the params are allocated
	   separately in a DATA_BLOB, so we need to do our own range
	   checking */
	if (offset >= blob->length) {
		*str = NULL;
		return 0;
	}
	
	return req_pull_string(req, str, 
			       blob->data + offset, 
			       blob->length - offset,
			       STR_NO_RANGE_CHECK | flags);
}

/*
  push a string into the data section of a trans2 request
  return the number of bytes consumed in the output
*/
static size_t trans2_push_data_string(struct smbsrv_request *req, 
				      struct smb_trans2 *trans,
				      uint16_t len_offset,
				      uint16_t offset,
				      const WIRE_STRING *str,
				      int dest_len,
				      int flags)
{
	int alignment = 0, ret = 0, pkt_len;

	/* we use STR_NO_RANGE_CHECK because the params are allocated
	   separately in a DATA_BLOB, so we need to do our own range
	   checking */
	if (!str->s || offset >= trans->out.data.length) {
		if (flags & STR_LEN8BIT) {
			SCVAL(trans->out.data.data, len_offset, 0);
		} else {
			SIVAL(trans->out.data.data, len_offset, 0);
		}
		return 0;
	}

	flags |= STR_NO_RANGE_CHECK;

	if (dest_len == -1 || (dest_len > trans->out.data.length - offset)) {
		dest_len = trans->out.data.length - offset;
	}

	if (!(flags & (STR_ASCII|STR_UNICODE))) {
		flags |= (req->flags2 & FLAGS2_UNICODE_STRINGS) ? STR_UNICODE : STR_ASCII;
	}

	if ((offset&1) && (flags & STR_UNICODE) && !(flags & STR_NOALIGN)) {
		alignment = 1;
		if (dest_len > 0) {
			SCVAL(trans->out.data.data + offset, 0, 0);
			ret = push_string(trans->out.data.data + offset + 1, str->s, dest_len-1, flags);
		}
	} else {
		ret = push_string(trans->out.data.data + offset, str->s, dest_len, flags);
	}

	/* sometimes the string needs to be terminated, but the length
	   on the wire must not include the termination! */
	pkt_len = ret;

	if ((flags & STR_LEN_NOTERM) && (flags & STR_TERMINATE)) {
		if ((flags & STR_UNICODE) && ret >= 2) {
			pkt_len = ret-2;
		}
		if ((flags & STR_ASCII) && ret >= 1) {
			pkt_len = ret-1;
		}
	}	

	if (flags & STR_LEN8BIT) {
		SCVAL(trans->out.data.data, len_offset, pkt_len);
	} else {
		SIVAL(trans->out.data.data, len_offset, pkt_len);
	}

	return ret + alignment;
}

/*
  append a string to the data section of a trans2 reply
  len_offset points to the place in the packet where the length field
  should go
*/
static void trans2_append_data_string(struct smbsrv_request *req, 
					struct smb_trans2 *trans,
					const WIRE_STRING *str,
					uint_t len_offset,
					int flags)
{
	size_t ret;
	uint16_t offset;
	const int max_bytes_per_char = 3;

	offset = trans->out.data.length;
	trans2_grow_data(req, trans, offset + (2+strlen_m(str->s))*max_bytes_per_char);
	ret = trans2_push_data_string(req, trans, len_offset, offset, str, -1, flags);
	trans2_grow_data(req, trans, offset + ret);
}


/*
  trans2 qfsinfo implementation
*/
static NTSTATUS trans2_qfsinfo(struct smbsrv_request *req, struct smb_trans2 *trans)
{
	union smb_fsinfo fsinfo;
	NTSTATUS status;
	uint16_t level;
	uint_t i;
	DATA_BLOB guid_blob;

	/* make sure we got enough parameters */
	if (trans->in.params.length != 2) {
		return NT_STATUS_FOOBAR;
	}

	level = SVAL(trans->in.params.data, 0);

	switch (level) {
	case SMB_QFS_ALLOCATION:
		fsinfo.allocation.level = RAW_QFS_ALLOCATION;

		status = req->tcon->ntvfs_ops->fsinfo(req, &fsinfo);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}

		trans2_setup_reply(req, trans, 0, 18, 0);

		SIVAL(trans->out.data.data,  0, fsinfo.allocation.out.fs_id);
		SIVAL(trans->out.data.data,  4, fsinfo.allocation.out.sectors_per_unit);
		SIVAL(trans->out.data.data,  8, fsinfo.allocation.out.total_alloc_units);
		SIVAL(trans->out.data.data, 12, fsinfo.allocation.out.avail_alloc_units);
		SSVAL(trans->out.data.data, 16, fsinfo.allocation.out.bytes_per_sector);

		return NT_STATUS_OK;

	case SMB_QFS_VOLUME:
		fsinfo.volume.level = RAW_QFS_VOLUME;

		status = req->tcon->ntvfs_ops->fsinfo(req, &fsinfo);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}

		trans2_setup_reply(req, trans, 0, 5, 0);

		SIVAL(trans->out.data.data,       0, fsinfo.volume.out.serial_number);
		/* w2k3 implements this incorrectly for unicode - it
		 * leaves the last byte off the string */
		trans2_append_data_string(req, trans, 
					  &fsinfo.volume.out.volume_name, 
					  4, STR_LEN8BIT|STR_NOALIGN);

		return NT_STATUS_OK;

	case SMB_QFS_VOLUME_INFO:
	case SMB_QFS_VOLUME_INFORMATION:
		fsinfo.volume_info.level = RAW_QFS_VOLUME_INFO;

		status = req->tcon->ntvfs_ops->fsinfo(req, &fsinfo);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}

		trans2_setup_reply(req, trans, 0, 18, 0);

		push_nttime(trans->out.data.data, 0, fsinfo.volume_info.out.create_time);
		SIVAL(trans->out.data.data,       8, fsinfo.volume_info.out.serial_number);
		SSVAL(trans->out.data.data,      16, 0); /* padding */
		trans2_append_data_string(req, trans, 
					  &fsinfo.volume_info.out.volume_name, 
					  12, STR_UNICODE);

		return NT_STATUS_OK;

	case SMB_QFS_SIZE_INFO:
	case SMB_QFS_SIZE_INFORMATION:
		fsinfo.size_info.level = RAW_QFS_SIZE_INFO;

		status = req->tcon->ntvfs_ops->fsinfo(req, &fsinfo);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}

		trans2_setup_reply(req, trans, 0, 24, 0);

		SBVAL(trans->out.data.data,  0, fsinfo.size_info.out.total_alloc_units);
		SBVAL(trans->out.data.data,  8, fsinfo.size_info.out.avail_alloc_units);
		SIVAL(trans->out.data.data, 16, fsinfo.size_info.out.sectors_per_unit);
		SIVAL(trans->out.data.data, 20, fsinfo.size_info.out.bytes_per_sector);

		return NT_STATUS_OK;

	case SMB_QFS_DEVICE_INFO:
	case SMB_QFS_DEVICE_INFORMATION:
		fsinfo.device_info.level = RAW_QFS_DEVICE_INFO;

		status = req->tcon->ntvfs_ops->fsinfo(req, &fsinfo);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
		trans2_setup_reply(req, trans, 0, 8, 0);
		SIVAL(trans->out.data.data,      0, fsinfo.device_info.out.device_type);
		SIVAL(trans->out.data.data,      4, fsinfo.device_info.out.characteristics);
		return NT_STATUS_OK;


	case SMB_QFS_ATTRIBUTE_INFO:
	case SMB_QFS_ATTRIBUTE_INFORMATION:
		fsinfo.attribute_info.level = RAW_QFS_ATTRIBUTE_INFO;

		status = req->tcon->ntvfs_ops->fsinfo(req, &fsinfo);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}

		trans2_setup_reply(req, trans, 0, 12, 0);

		SIVAL(trans->out.data.data, 0, fsinfo.attribute_info.out.fs_attr);
		SIVAL(trans->out.data.data, 4, fsinfo.attribute_info.out.max_file_component_length);
		/* this must not be null terminated or win98 gets
		   confused!  also note that w2k3 returns this as
		   unicode even when ascii is negotiated */
		trans2_append_data_string(req, trans, 
					  &fsinfo.attribute_info.out.fs_type,
					  8, STR_UNICODE);
		return NT_STATUS_OK;


	case SMB_QFS_QUOTA_INFORMATION:
		fsinfo.quota_information.level = RAW_QFS_QUOTA_INFORMATION;

		status = req->tcon->ntvfs_ops->fsinfo(req, &fsinfo);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}

		trans2_setup_reply(req, trans, 0, 48, 0);

		SBVAL(trans->out.data.data,   0, fsinfo.quota_information.out.unknown[0]);
		SBVAL(trans->out.data.data,   8, fsinfo.quota_information.out.unknown[1]);
		SBVAL(trans->out.data.data,  16, fsinfo.quota_information.out.unknown[2]);
		SBVAL(trans->out.data.data,  24, fsinfo.quota_information.out.quota_soft);
		SBVAL(trans->out.data.data,  32, fsinfo.quota_information.out.quota_hard);
		SBVAL(trans->out.data.data,  40, fsinfo.quota_information.out.quota_flags);

		return NT_STATUS_OK;


	case SMB_QFS_FULL_SIZE_INFORMATION:
		fsinfo.full_size_information.level = RAW_QFS_FULL_SIZE_INFORMATION;

		status = req->tcon->ntvfs_ops->fsinfo(req, &fsinfo);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}

		trans2_setup_reply(req, trans, 0, 32, 0);

		SBVAL(trans->out.data.data,  0, fsinfo.full_size_information.out.total_alloc_units);
		SBVAL(trans->out.data.data,  8, fsinfo.full_size_information.out.call_avail_alloc_units);
		SBVAL(trans->out.data.data, 16, fsinfo.full_size_information.out.actual_avail_alloc_units);
		SIVAL(trans->out.data.data, 24, fsinfo.full_size_information.out.sectors_per_unit);
		SIVAL(trans->out.data.data, 28, fsinfo.full_size_information.out.bytes_per_sector);

		return NT_STATUS_OK;

	case SMB_QFS_OBJECTID_INFORMATION:
		fsinfo.objectid_information.level = RAW_QFS_OBJECTID_INFORMATION;

		status = req->tcon->ntvfs_ops->fsinfo(req, &fsinfo);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}

		trans2_setup_reply(req, trans, 0, 64, 0);

		status = ndr_push_struct_blob(&guid_blob, req, 
					      &fsinfo.objectid_information.out.guid,
					      (ndr_push_flags_fn_t)ndr_push_GUID);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}

		memcpy(trans->out.data.data, guid_blob.data, GUID_SIZE);

		for (i=0;i<6;i++) {
			SBVAL(trans->out.data.data, 16 + 8*i, fsinfo.objectid_information.out.unknown[i]);
		}
		return NT_STATUS_OK;
	}

	return NT_STATUS_INVALID_LEVEL;
}

/*
  fill in the reply from a qpathinfo or qfileinfo call
*/
static NTSTATUS trans2_fileinfo_fill(struct smbsrv_request *req, struct smb_trans2 *trans,
				     union smb_fileinfo *st)
{
	uint_t i;
	
	switch (st->generic.level) {
	case RAW_FILEINFO_GENERIC:
	case RAW_FILEINFO_GETATTR:
	case RAW_FILEINFO_GETATTRE:
		/* handled elsewhere */
		return NT_STATUS_INVALID_LEVEL;

	case RAW_FILEINFO_BASIC_INFO:
	case RAW_FILEINFO_BASIC_INFORMATION:
		trans2_setup_reply(req, trans, 2, 40, 0);

		SSVAL(trans->out.params.data, 0, 0);
		push_nttime(trans->out.data.data,  0, st->basic_info.out.create_time);
		push_nttime(trans->out.data.data,  8, st->basic_info.out.access_time);
		push_nttime(trans->out.data.data, 16, st->basic_info.out.write_time);
		push_nttime(trans->out.data.data, 24, st->basic_info.out.change_time);
		SIVAL(trans->out.data.data,       32, st->basic_info.out.attrib);
		SIVAL(trans->out.data.data,       36, 0); /* padding */
		return NT_STATUS_OK;

	case RAW_FILEINFO_STANDARD:
		trans2_setup_reply(req, trans, 2, 22, 0);

		SSVAL(trans->out.params.data, 0, 0);
		srv_push_dos_date2(req->smb_conn, trans->out.data.data, 0, st->standard.out.create_time);
		srv_push_dos_date2(req->smb_conn, trans->out.data.data, 4, st->standard.out.access_time);
		srv_push_dos_date2(req->smb_conn, trans->out.data.data, 8, st->standard.out.write_time);
		SIVAL(trans->out.data.data,        12, st->standard.out.size);
		SIVAL(trans->out.data.data,        16, st->standard.out.alloc_size);
		SSVAL(trans->out.data.data,        20, st->standard.out.attrib);
		return NT_STATUS_OK;

	case RAW_FILEINFO_EA_SIZE:
		trans2_setup_reply(req, trans, 2, 26, 0);

		SSVAL(trans->out.params.data, 0, 0);
		srv_push_dos_date2(req->smb_conn, trans->out.data.data, 0, st->ea_size.out.create_time);
		srv_push_dos_date2(req->smb_conn, trans->out.data.data, 4, st->ea_size.out.access_time);
		srv_push_dos_date2(req->smb_conn, trans->out.data.data, 8, st->ea_size.out.write_time);
		SIVAL(trans->out.data.data,        12, st->ea_size.out.size);
		SIVAL(trans->out.data.data,        16, st->ea_size.out.alloc_size);
		SSVAL(trans->out.data.data,        20, st->ea_size.out.attrib);
		SIVAL(trans->out.data.data,        22, st->ea_size.out.ea_size);
		return NT_STATUS_OK;

	case RAW_FILEINFO_NETWORK_OPEN_INFORMATION:
		trans2_setup_reply(req, trans, 2, 56, 0);

		SSVAL(trans->out.params.data, 0, 0);
		push_nttime(trans->out.data.data,  0, st->network_open_information.out.create_time);
		push_nttime(trans->out.data.data,  8, st->network_open_information.out.access_time);
		push_nttime(trans->out.data.data, 16, st->network_open_information.out.write_time);
		push_nttime(trans->out.data.data, 24, st->network_open_information.out.change_time);
		SBVAL(trans->out.data.data,       32, st->network_open_information.out.alloc_size);
		SBVAL(trans->out.data.data,       40, st->network_open_information.out.size);
		SIVAL(trans->out.data.data,       48, st->network_open_information.out.attrib);
		SIVAL(trans->out.data.data,       52, 0); /* padding */
		return NT_STATUS_OK;

	case RAW_FILEINFO_STANDARD_INFO:
	case RAW_FILEINFO_STANDARD_INFORMATION:
		trans2_setup_reply(req, trans, 2, 24, 0);
		SSVAL(trans->out.params.data, 0, 0);
		SBVAL(trans->out.data.data,  0, st->standard_info.out.alloc_size);
		SBVAL(trans->out.data.data,  8, st->standard_info.out.size);
		SIVAL(trans->out.data.data, 16, st->standard_info.out.nlink);
		SCVAL(trans->out.data.data, 20, st->standard_info.out.delete_pending);
		SCVAL(trans->out.data.data, 21, st->standard_info.out.directory);
		SSVAL(trans->out.data.data, 22, 0); /* padding */
		return NT_STATUS_OK;

	case RAW_FILEINFO_ATTRIBUTE_TAG_INFORMATION:
		trans2_setup_reply(req, trans, 2, 8, 0);
		SSVAL(trans->out.params.data, 0, 0);
		SIVAL(trans->out.data.data,  0, st->attribute_tag_information.out.attrib);
		SIVAL(trans->out.data.data,  4, st->attribute_tag_information.out.reparse_tag);
		return NT_STATUS_OK;

	case RAW_FILEINFO_EA_INFO:
	case RAW_FILEINFO_EA_INFORMATION:
		trans2_setup_reply(req, trans, 2, 4, 0);
		SSVAL(trans->out.params.data, 0, 0);
		SIVAL(trans->out.data.data,  0, st->ea_info.out.ea_size);
		return NT_STATUS_OK;

	case RAW_FILEINFO_MODE_INFORMATION:
		trans2_setup_reply(req, trans, 2, 4, 0);
		SSVAL(trans->out.params.data, 0, 0);
		SIVAL(trans->out.data.data,  0, st->mode_information.out.mode);
		return NT_STATUS_OK;

	case RAW_FILEINFO_ALIGNMENT_INFORMATION:
		trans2_setup_reply(req, trans, 2, 4, 0);
		SSVAL(trans->out.params.data, 0, 0);
		SIVAL(trans->out.data.data,  0, 
		      st->alignment_information.out.alignment_requirement);
		return NT_STATUS_OK;

	case RAW_FILEINFO_ALL_EAS:
		if (st->all_eas.out.num_eas == 0) {
			trans2_setup_reply(req, trans, 2, 4, 0);
			SSVAL(trans->out.params.data, 0, 0);
			SIVAL(trans->out.data.data,  0, 0);
		} else {
			uint32_t list_size = ea_list_size(st->all_eas.out.num_eas,
							st->all_eas.out.eas);
			trans2_setup_reply(req, trans, 2, list_size, 0);
			SSVAL(trans->out.params.data, 0, 0);
			ea_put_list(trans->out.data.data, 
				    st->all_eas.out.num_eas, st->all_eas.out.eas);
		}
		return NT_STATUS_OK;

	case RAW_FILEINFO_ACCESS_INFORMATION:
		trans2_setup_reply(req, trans, 2, 4, 0);
		SSVAL(trans->out.params.data, 0, 0);
		SIVAL(trans->out.data.data,  0, st->access_information.out.access_flags);
		return NT_STATUS_OK;

	case RAW_FILEINFO_POSITION_INFORMATION:
		trans2_setup_reply(req, trans, 2, 8, 0);
		SSVAL(trans->out.params.data, 0, 0);
		SBVAL(trans->out.data.data,  0, st->position_information.out.position);
		return NT_STATUS_OK;

	case RAW_FILEINFO_COMPRESSION_INFO:
	case RAW_FILEINFO_COMPRESSION_INFORMATION:
		trans2_setup_reply(req, trans, 2, 16, 0);
		SSVAL(trans->out.params.data, 0, 0);
		SBVAL(trans->out.data.data,  0, st->compression_info.out.compressed_size);
		SSVAL(trans->out.data.data,  8, st->compression_info.out.format);
		SCVAL(trans->out.data.data, 10, st->compression_info.out.unit_shift);
		SCVAL(trans->out.data.data, 11, st->compression_info.out.chunk_shift);
		SCVAL(trans->out.data.data, 12, st->compression_info.out.cluster_shift);
		SSVAL(trans->out.data.data, 13, 0); /* 3 bytes padding */
		SCVAL(trans->out.data.data, 15, 0);
		return NT_STATUS_OK;

	case RAW_FILEINFO_IS_NAME_VALID:
		trans2_setup_reply(req, trans, 2, 0, 0);
		SSVAL(trans->out.params.data, 0, 0);
		return NT_STATUS_OK;

	case RAW_FILEINFO_INTERNAL_INFORMATION:
		trans2_setup_reply(req, trans, 2, 8, 0);
		SSVAL(trans->out.params.data, 0, 0);
		SBVAL(trans->out.data.data,  0, st->internal_information.out.file_id);
		return NT_STATUS_OK;

	case RAW_FILEINFO_ALL_INFO:
	case RAW_FILEINFO_ALL_INFORMATION:
		trans2_setup_reply(req, trans, 2, 72, 0);

		SSVAL(trans->out.params.data, 0, 0);
		push_nttime(trans->out.data.data,  0, st->all_info.out.create_time);
		push_nttime(trans->out.data.data,  8, st->all_info.out.access_time);
		push_nttime(trans->out.data.data, 16, st->all_info.out.write_time);
		push_nttime(trans->out.data.data, 24, st->all_info.out.change_time);
		SIVAL(trans->out.data.data,       32, st->all_info.out.attrib);
		SIVAL(trans->out.data.data,       36, 0);
		SBVAL(trans->out.data.data,       40, st->all_info.out.alloc_size);
		SBVAL(trans->out.data.data,       48, st->all_info.out.size);
		SIVAL(trans->out.data.data,       56, st->all_info.out.nlink);
		SCVAL(trans->out.data.data,       60, st->all_info.out.delete_pending);
		SCVAL(trans->out.data.data,       61, st->all_info.out.directory);
		SSVAL(trans->out.data.data,       62, 0); /* padding */
		SIVAL(trans->out.data.data,       64, st->all_info.out.ea_size);
		trans2_append_data_string(req, trans, &st->all_info.out.fname, 
					  68, STR_UNICODE);
		return NT_STATUS_OK;

	case RAW_FILEINFO_NAME_INFO:
	case RAW_FILEINFO_NAME_INFORMATION:
		trans2_setup_reply(req, trans, 2, 4, 0);
		SSVAL(trans->out.params.data, 0, 0);
		trans2_append_data_string(req, trans, &st->name_info.out.fname, 0, STR_UNICODE);
		return NT_STATUS_OK;

	case RAW_FILEINFO_ALT_NAME_INFO:
	case RAW_FILEINFO_ALT_NAME_INFORMATION:
		trans2_setup_reply(req, trans, 2, 4, 0);
		SSVAL(trans->out.params.data, 0, 0);
		trans2_append_data_string(req, trans, &st->alt_name_info.out.fname, 0, STR_UNICODE);
		return NT_STATUS_OK;

	case RAW_FILEINFO_STREAM_INFO:
	case RAW_FILEINFO_STREAM_INFORMATION:
		trans2_setup_reply(req, trans, 2, 0, 0);

		SSVAL(trans->out.params.data, 0, 0);

		for (i=0;i<st->stream_info.out.num_streams;i++) {
			uint16_t data_size = trans->out.data.length;
			char *data;

			trans2_grow_data(req, trans, data_size + 24);
			data = trans->out.data.data + data_size;
			SBVAL(data,  8, st->stream_info.out.streams[i].size);
			SBVAL(data, 16, st->stream_info.out.streams[i].alloc_size);
			trans2_append_data_string(req, trans, 
						  &st->stream_info.out.streams[i].stream_name, 
						  data_size + 4, STR_UNICODE);
			if (i == st->stream_info.out.num_streams - 1) {
				SIVAL(trans->out.data.data, data_size, 0);
			} else {
				trans2_grow_data_fill(req, trans, (trans->out.data.length+7)&~7);
				SIVAL(trans->out.data.data, data_size, 
				      trans->out.data.length - data_size);
			}
		}
		return NT_STATUS_OK;
	}

	return NT_STATUS_INVALID_LEVEL;
}

/*
  trans2 qpathinfo implementation
*/
static NTSTATUS trans2_qpathinfo(struct smbsrv_request *req, struct smb_trans2 *trans)
{
	union smb_fileinfo st;
	NTSTATUS status;
	uint16_t level;

	/* make sure we got enough parameters */
	if (trans->in.params.length < 8) {
		return NT_STATUS_FOOBAR;
	}

	level = SVAL(trans->in.params.data, 0);

	trans2_pull_blob_string(req, &trans->in.params, 6, &st.generic.in.fname, 0);
	if (st.generic.in.fname == NULL) {
		return NT_STATUS_FOOBAR;
	}

	/* work out the backend level - we make it 1-1 in the header */
	st.generic.level = (enum smb_fileinfo_level)level;
	if (st.generic.level >= RAW_FILEINFO_GENERIC) {
		return NT_STATUS_INVALID_LEVEL;
	}

	/* call the backend */
	status = req->tcon->ntvfs_ops->qpathinfo(req, &st);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	/* fill in the reply parameters */
	status = trans2_fileinfo_fill(req, trans, &st);

	return status;
}


/*
  trans2 qpathinfo implementation
*/
static NTSTATUS trans2_qfileinfo(struct smbsrv_request *req, struct smb_trans2 *trans)
{
	union smb_fileinfo st;
	NTSTATUS status;
	uint16_t level;

	/* make sure we got enough parameters */
	if (trans->in.params.length < 4) {
		return NT_STATUS_FOOBAR;
	}

	st.generic.in.fnum  = SVAL(trans->in.params.data, 0);
	level = SVAL(trans->in.params.data, 2);

	/* work out the backend level - we make it 1-1 in the header */
	st.generic.level = (enum smb_fileinfo_level)level;
	if (st.generic.level >= RAW_FILEINFO_GENERIC) {
		return NT_STATUS_INVALID_LEVEL;
	}

	/* call the backend */
	status = req->tcon->ntvfs_ops->qfileinfo(req, &st);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	/* fill in the reply parameters */
	status = trans2_fileinfo_fill(req, trans, &st);

	return status;
}


/*
  parse a trans2 setfileinfo/setpathinfo data blob
*/
static NTSTATUS trans2_parse_sfileinfo(struct smbsrv_request *req,
				       union smb_setfileinfo *st,
				       const DATA_BLOB *blob)
{
	uint32_t len;

	switch (st->generic.level) {
	case RAW_SFILEINFO_GENERIC:
	case RAW_SFILEINFO_SETATTR:
	case RAW_SFILEINFO_SETATTRE:
		/* handled elsewhere */
		return NT_STATUS_INVALID_LEVEL;

	case RAW_SFILEINFO_STANDARD:
		CHECK_MIN_BLOB_SIZE(blob, 12);
		st->standard.in.create_time = srv_pull_dos_date2(req->smb_conn, blob->data + 0);
		st->standard.in.access_time = srv_pull_dos_date2(req->smb_conn, blob->data + 4);
		st->standard.in.write_time  = srv_pull_dos_date2(req->smb_conn, blob->data + 8);
		return NT_STATUS_OK;

	case RAW_SFILEINFO_EA_SET:
		CHECK_MIN_BLOB_SIZE(blob, 4);
		len = IVAL(blob->data, 0);
		if (len > blob->length || len < 4) {
			return NT_STATUS_INFO_LENGTH_MISMATCH;
		}
		{
			DATA_BLOB blob2;
			blob2.data = blob->data+4;
			blob2.length = len-4;
			len = ea_pull_struct(&blob2, req, &st->ea_set.in.ea);
		}
		if (len == 0) {
			return NT_STATUS_INVALID_PARAMETER;
		}
		return NT_STATUS_OK;

	case SMB_SFILEINFO_BASIC_INFO:
	case SMB_SFILEINFO_BASIC_INFORMATION:
		CHECK_MIN_BLOB_SIZE(blob, 36);
		st->basic_info.in.create_time = pull_nttime(blob->data,  0);
		st->basic_info.in.access_time = pull_nttime(blob->data,  8);
		st->basic_info.in.write_time =  pull_nttime(blob->data, 16);
		st->basic_info.in.change_time = pull_nttime(blob->data, 24);
		st->basic_info.in.attrib =      IVAL(blob->data,        32);
		return NT_STATUS_OK;

	case SMB_SFILEINFO_DISPOSITION_INFO:
	case SMB_SFILEINFO_DISPOSITION_INFORMATION:
		CHECK_MIN_BLOB_SIZE(blob, 1);
		st->disposition_info.in.delete_on_close = CVAL(blob->data, 0);
		return NT_STATUS_OK;

	case SMB_SFILEINFO_ALLOCATION_INFO:
	case SMB_SFILEINFO_ALLOCATION_INFORMATION:
		CHECK_MIN_BLOB_SIZE(blob, 8);
		st->allocation_info.in.alloc_size = BVAL(blob->data, 0);
		return NT_STATUS_OK;				

	case RAW_SFILEINFO_END_OF_FILE_INFO:
	case RAW_SFILEINFO_END_OF_FILE_INFORMATION:
		CHECK_MIN_BLOB_SIZE(blob, 8);
		st->end_of_file_info.in.size = BVAL(blob->data, 0);
		return NT_STATUS_OK;

	case RAW_SFILEINFO_RENAME_INFORMATION: {
		DATA_BLOB blob2;

		CHECK_MIN_BLOB_SIZE(blob, 12);
		st->rename_information.in.overwrite = CVAL(blob->data, 0);
		st->rename_information.in.root_fid  = IVAL(blob->data, 4);
		len                                 = IVAL(blob->data, 8);
		blob2.data = blob->data+12;
		blob2.length = MIN(blob->length, len);
		trans2_pull_blob_string(req, &blob2, 0, 
					&st->rename_information.in.new_name, STR_UNICODE);
		return NT_STATUS_OK;
	}

	case RAW_SFILEINFO_POSITION_INFORMATION:
		CHECK_MIN_BLOB_SIZE(blob, 8);
		st->position_information.in.position = BVAL(blob->data, 0);
		return NT_STATUS_OK;

	case RAW_SFILEINFO_MODE_INFORMATION:
		CHECK_MIN_BLOB_SIZE(blob, 4);
		st->mode_information.in.mode = IVAL(blob->data, 0);
		return NT_STATUS_OK;
	}

	return NT_STATUS_INVALID_LEVEL;
}

/*
  trans2 setfileinfo implementation
*/
static NTSTATUS trans2_setfileinfo(struct smbsrv_request *req, struct smb_trans2 *trans)
{
	union smb_setfileinfo st;
	NTSTATUS status;
	uint16_t level, fnum;
	DATA_BLOB *blob;

	/* make sure we got enough parameters */
	if (trans->in.params.length < 4) {
		return NT_STATUS_FOOBAR;
	}

	fnum  = SVAL(trans->in.params.data, 0);
	level = SVAL(trans->in.params.data, 2);

	blob = &trans->in.data;

	st.generic.file.fnum = fnum;
	st.generic.level = (enum smb_setfileinfo_level)level;

	status = trans2_parse_sfileinfo(req, &st, blob);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	status = req->tcon->ntvfs_ops->setfileinfo(req, &st);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	trans2_setup_reply(req, trans, 2, 0, 0);
	SSVAL(trans->out.params.data, 0, 0);
	return NT_STATUS_OK;
}

/*
  trans2 setpathinfo implementation
*/
static NTSTATUS trans2_setpathinfo(struct smbsrv_request *req, struct smb_trans2 *trans)
{
	union smb_setfileinfo st;
	NTSTATUS status;
	uint16_t level;
	DATA_BLOB *blob;

	/* make sure we got enough parameters */
	if (trans->in.params.length < 4) {
		return NT_STATUS_FOOBAR;
	}

	level = SVAL(trans->in.params.data, 0);
	blob = &trans->in.data;
	st.generic.level = (enum smb_setfileinfo_level)level;

	trans2_pull_blob_string(req, &trans->in.params, 6, &st.generic.file.fname, 0);
	if (st.generic.file.fname == NULL) {
		return NT_STATUS_FOOBAR;
	}

	status = trans2_parse_sfileinfo(req, &st, blob);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	status = req->tcon->ntvfs_ops->setpathinfo(req, &st);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	trans2_setup_reply(req, trans, 2, 0, 0);
	SSVAL(trans->out.params.data, 0, 0);
	return NT_STATUS_OK;
}


/* a structure to encapsulate the state information about an in-progress ffirst/fnext operation */
struct find_state {
	struct smbsrv_request *req;
	struct smb_trans2 *trans;
	enum smb_search_level level;
	uint16_t last_entry_offset;
	uint16_t flags;
};

/*
  fill a single entry in a trans2 find reply 
*/
static void find_fill_info(struct smbsrv_request *req,
			   struct smb_trans2 *trans, 
			   struct find_state *state,
			   union smb_search_data *file)
{
	char *data;
	uint_t ofs = trans->out.data.length;

	switch (state->level) {
	case RAW_SEARCH_SEARCH:
	case RAW_SEARCH_FFIRST:
	case RAW_SEARCH_FUNIQUE:
	case RAW_SEARCH_GENERIC:
		/* handled elsewhere */
		break;

	case RAW_SEARCH_STANDARD:
		if (state->flags & FLAG_TRANS2_FIND_REQUIRE_RESUME) {
			trans2_grow_data(req, trans, ofs + 27);
			SIVAL(trans->out.data.data, ofs, file->standard.resume_key);
			ofs += 4;
		} else {
			trans2_grow_data(req, trans, ofs + 23);
		}
		data = trans->out.data.data + ofs;
		srv_push_dos_date2(req->smb_conn, data, 0, file->standard.create_time);
		srv_push_dos_date2(req->smb_conn, data, 4, file->standard.access_time);
		srv_push_dos_date2(req->smb_conn, data, 8, file->standard.write_time);
		SIVAL(data, 12, file->standard.size);
		SIVAL(data, 16, file->standard.alloc_size);
		SSVAL(data, 20, file->standard.attrib);
		trans2_append_data_string(req, trans, &file->standard.name, 
					  ofs + 22, STR_LEN8BIT | STR_TERMINATE | STR_LEN_NOTERM);
		break;

	case RAW_SEARCH_EA_SIZE:
		if (state->flags & FLAG_TRANS2_FIND_REQUIRE_RESUME) {
			trans2_grow_data(req, trans, ofs + 31);
			SIVAL(trans->out.data.data, ofs, file->ea_size.resume_key);
			ofs += 4;
		} else {
			trans2_grow_data(req, trans, ofs + 27);
		}
		data = trans->out.data.data + ofs;
		srv_push_dos_date2(req->smb_conn, data, 0, file->ea_size.create_time);
		srv_push_dos_date2(req->smb_conn, data, 4, file->ea_size.access_time);
		srv_push_dos_date2(req->smb_conn, data, 8, file->ea_size.write_time);
		SIVAL(data, 12, file->ea_size.size);
		SIVAL(data, 16, file->ea_size.alloc_size);
		SSVAL(data, 20, file->ea_size.attrib);
		SIVAL(data, 22, file->ea_size.ea_size);
		trans2_append_data_string(req, trans, &file->ea_size.name, 
					  ofs + 26, STR_LEN8BIT | STR_NOALIGN);
		trans2_grow_data(req, trans, trans->out.data.length + 1);
		trans->out.data.data[trans->out.data.length-1] = 0;
		break;

	case RAW_SEARCH_DIRECTORY_INFO:
		trans2_grow_data(req, trans, ofs + 64);
		data = trans->out.data.data + ofs;
		SIVAL(data,          4, file->directory_info.file_index);
		push_nttime(data,    8, file->directory_info.create_time);
		push_nttime(data,   16, file->directory_info.access_time);
		push_nttime(data,   24, file->directory_info.write_time);
		push_nttime(data,   32, file->directory_info.change_time);
		SBVAL(data,         40, file->directory_info.size);
		SBVAL(data,         48, file->directory_info.alloc_size);
		SIVAL(data,         56, file->directory_info.attrib);
		trans2_append_data_string(req, trans, &file->directory_info.name, 
					  ofs + 60, STR_TERMINATE_ASCII);
		data = trans->out.data.data + ofs;
		SIVAL(data,          0, trans->out.data.length - ofs);
		break;

	case RAW_SEARCH_FULL_DIRECTORY_INFO:
		trans2_grow_data(req, trans, ofs + 68);
		data = trans->out.data.data + ofs;
		SIVAL(data,          4, file->full_directory_info.file_index);
		push_nttime(data,    8, file->full_directory_info.create_time);
		push_nttime(data,   16, file->full_directory_info.access_time);
		push_nttime(data,   24, file->full_directory_info.write_time);
		push_nttime(data,   32, file->full_directory_info.change_time);
		SBVAL(data,         40, file->full_directory_info.size);
		SBVAL(data,         48, file->full_directory_info.alloc_size);
		SIVAL(data,         56, file->full_directory_info.attrib);
		SIVAL(data,         64, file->full_directory_info.ea_size);
		trans2_append_data_string(req, trans, &file->full_directory_info.name, 
					  ofs + 60, STR_TERMINATE_ASCII);
		data = trans->out.data.data + ofs;
		SIVAL(data,          0, trans->out.data.length - ofs);
		break;

	case RAW_SEARCH_NAME_INFO:
		trans2_grow_data(req, trans, ofs + 12);
		data = trans->out.data.data + ofs;
		SIVAL(data,          4, file->name_info.file_index);
		trans2_append_data_string(req, trans, &file->name_info.name, 
					  ofs + 8, STR_TERMINATE_ASCII);
		data = trans->out.data.data + ofs;
		SIVAL(data,          0, trans->out.data.length - ofs);
		break;

	case RAW_SEARCH_BOTH_DIRECTORY_INFO:
		trans2_grow_data(req, trans, ofs + 94);
		data = trans->out.data.data + ofs;
		SIVAL(data,          4, file->both_directory_info.file_index);
		push_nttime(data,    8, file->both_directory_info.create_time);
		push_nttime(data,   16, file->both_directory_info.access_time);
		push_nttime(data,   24, file->both_directory_info.write_time);
		push_nttime(data,   32, file->both_directory_info.change_time);
		SBVAL(data,         40, file->both_directory_info.size);
		SBVAL(data,         48, file->both_directory_info.alloc_size);
		SIVAL(data,         56, file->both_directory_info.attrib);
		SIVAL(data,         64, file->both_directory_info.ea_size);
		SCVAL(data,         69, 0); /* reserved */
		memset(data+70,0,24);
		trans2_push_data_string(req, trans, 
					68 + ofs, 70 + ofs, 
					&file->both_directory_info.short_name, 
					24, STR_UNICODE | STR_LEN8BIT);
		trans2_append_data_string(req, trans, &file->both_directory_info.name, 
					  ofs + 60, STR_TERMINATE_ASCII);
		data = trans->out.data.data + ofs;
		SIVAL(data,          0, trans->out.data.length - ofs);
		break;

	case RAW_SEARCH_ID_FULL_DIRECTORY_INFO:
		trans2_grow_data(req, trans, ofs + 80);
		data = trans->out.data.data + ofs;
		SIVAL(data,          4, file->id_full_directory_info.file_index);
		push_nttime(data,    8, file->id_full_directory_info.create_time);
		push_nttime(data,   16, file->id_full_directory_info.access_time);
		push_nttime(data,   24, file->id_full_directory_info.write_time);
		push_nttime(data,   32, file->id_full_directory_info.change_time);
		SBVAL(data,         40, file->id_full_directory_info.size);
		SBVAL(data,         48, file->id_full_directory_info.alloc_size);
		SIVAL(data,         56, file->id_full_directory_info.attrib);
		SIVAL(data,         64, file->id_full_directory_info.ea_size);
		SIVAL(data,         68, 0); /* padding */
		SBVAL(data,         72, file->id_full_directory_info.file_id);
		trans2_append_data_string(req, trans, &file->id_full_directory_info.name, 
					  ofs + 60, STR_TERMINATE_ASCII);
		data = trans->out.data.data + ofs;
		SIVAL(data,          0, trans->out.data.length - ofs);
		break;

	case RAW_SEARCH_ID_BOTH_DIRECTORY_INFO:
		trans2_grow_data(req, trans, ofs + 104);
		data = trans->out.data.data + ofs;
		SIVAL(data,          4, file->id_both_directory_info.file_index);
		push_nttime(data,    8, file->id_both_directory_info.create_time);
		push_nttime(data,   16, file->id_both_directory_info.access_time);
		push_nttime(data,   24, file->id_both_directory_info.write_time);
		push_nttime(data,   32, file->id_both_directory_info.change_time);
		SBVAL(data,         40, file->id_both_directory_info.size);
		SBVAL(data,         48, file->id_both_directory_info.alloc_size);
		SIVAL(data,         56, file->id_both_directory_info.attrib);
		SIVAL(data,         64, file->id_both_directory_info.ea_size);
		SCVAL(data,         69, 0); /* reserved */
		memset(data+70,0,26);
		trans2_push_data_string(req, trans, 
					68 + ofs, 70 + ofs, 
					&file->id_both_directory_info.short_name, 
					24, STR_UNICODE | STR_LEN8BIT);
		SBVAL(data,         96, file->id_both_directory_info.file_id);
		trans2_append_data_string(req, trans, &file->id_both_directory_info.name, 
					  ofs + 60, STR_TERMINATE_ASCII);
		data = trans->out.data.data + ofs;
		SIVAL(data,          0, trans->out.data.length - ofs);
		break;
	}
}

/* callback function for trans2 findfirst/findnext */
static BOOL find_callback(void *private, union smb_search_data *file)
{
	struct find_state *state = (struct find_state *)private;
	struct smb_trans2 *trans = state->trans;
	uint_t old_length;

	old_length = trans->out.data.length;

	find_fill_info(state->req, trans, state, file);

	/* see if we have gone beyond the user specified maximum */
	if (trans->out.data.length > trans->in.max_data) {
		/* restore the old length and tell the backend to stop */
		trans2_grow_data(state->req, trans, old_length);
		return False;
	}

	state->last_entry_offset = old_length;	
	return True;
}


/*
  trans2 findfirst implementation
*/
static NTSTATUS trans2_findfirst(struct smbsrv_request *req, struct smb_trans2 *trans)
{
	union smb_search_first search;
	NTSTATUS status;
	uint16_t level;
	char *param;
	struct find_state state;

	/* make sure we got all the parameters */
	if (trans->in.params.length < 14) {
		return NT_STATUS_FOOBAR;
	}

	search.t2ffirst.in.search_attrib = SVAL(trans->in.params.data, 0);
	search.t2ffirst.in.max_count     = SVAL(trans->in.params.data, 2);
	search.t2ffirst.in.flags         = SVAL(trans->in.params.data, 4);
	level                            = SVAL(trans->in.params.data, 6);
	search.t2ffirst.in.storage_type  = IVAL(trans->in.params.data, 8);

	trans2_pull_blob_string(req, &trans->in.params, 12, &search.t2ffirst.in.pattern, 0);
	if (search.t2ffirst.in.pattern == NULL) {
		return NT_STATUS_FOOBAR;
	}

	search.t2ffirst.level = (enum smb_search_level)level;
	if (search.t2ffirst.level >= RAW_SEARCH_GENERIC) {
		return NT_STATUS_INVALID_LEVEL;
	}

	/* setup the private state structure that the backend will give us in the callback */
	state.req = req;
	state.trans = trans;
	state.level = search.t2ffirst.level;
	state.last_entry_offset = 0;
	state.flags = search.t2ffirst.in.flags;

	/* setup for just a header in the reply */
	trans2_setup_reply(req, trans, 10, 0, 0);

	/* call the backend */
	status = req->tcon->ntvfs_ops->search_first(req, &search, &state, find_callback);
	if (!NT_STATUS_IS_OK(status)) {
		trans2_setup_reply(req, trans, 0, 0, 0);
		return status;
	}

	/* fill in the findfirst reply header */
	param = trans->out.params.data;
	SSVAL(param, VWV(0), search.t2ffirst.out.handle);
	SSVAL(param, VWV(1), search.t2ffirst.out.count);
	SSVAL(param, VWV(2), search.t2ffirst.out.end_of_search);
	SSVAL(param, VWV(3), 0);
	SSVAL(param, VWV(4), state.last_entry_offset);

	return NT_STATUS_OK;
}


/*
  trans2 findnext implementation
*/
static NTSTATUS trans2_findnext(struct smbsrv_request *req, struct smb_trans2 *trans)
{
	union smb_search_next search;
	NTSTATUS status;
	uint16_t level;
	char *param;
	struct find_state state;

	/* make sure we got all the parameters */
	if (trans->in.params.length < 12) {
		return NT_STATUS_FOOBAR;
	}

	search.t2fnext.in.handle        = SVAL(trans->in.params.data, 0);
	search.t2fnext.in.max_count     = SVAL(trans->in.params.data, 2);
	level                           = SVAL(trans->in.params.data, 4);
	search.t2fnext.in.resume_key    = IVAL(trans->in.params.data, 6);
	search.t2fnext.in.flags         = SVAL(trans->in.params.data, 10);

	trans2_pull_blob_string(req, &trans->in.params, 12, &search.t2fnext.in.last_name, 0);
	if (search.t2fnext.in.last_name == NULL) {
		return NT_STATUS_FOOBAR;
	}

	search.t2fnext.level = (enum smb_search_level)level;
	if (search.t2fnext.level >= RAW_SEARCH_GENERIC) {
		return NT_STATUS_INVALID_LEVEL;
	}

	/* setup the private state structure that the backend will give us in the callback */
	state.req = req;
	state.trans = trans;
	state.level = search.t2fnext.level;
	state.last_entry_offset = 0;
	state.flags = search.t2fnext.in.flags;

	/* setup for just a header in the reply */
	trans2_setup_reply(req, trans, 8, 0, 0);

	/* call the backend */
	status = req->tcon->ntvfs_ops->search_next(req, &search, &state, find_callback);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	/* fill in the findfirst reply header */
	param = trans->out.params.data;
	SSVAL(param, VWV(0), search.t2fnext.out.count);
	SSVAL(param, VWV(1), search.t2fnext.out.end_of_search);
	SSVAL(param, VWV(2), 0);
	SSVAL(param, VWV(3), state.last_entry_offset);
	
	return NT_STATUS_OK;
}


/*
  backend for trans2 requests
*/
static NTSTATUS trans2_backend(struct smbsrv_request *req, struct smb_trans2 *trans)
{
	if (req->tcon->ntvfs_ops->trans2 != NULL) {
		/* direct trans2 pass thru */
		return req->tcon->ntvfs_ops->trans2(req, trans);
	}

	/* must have at least one setup word */
	if (trans->in.setup_count < 1) {
		return NT_STATUS_FOOBAR;
	}

	/* the trans2 command is in setup[0] */
	switch (trans->in.setup[0]) {
	case TRANSACT2_FINDFIRST:
		return trans2_findfirst(req, trans);
	case TRANSACT2_FINDNEXT:
		return trans2_findnext(req, trans);
	case TRANSACT2_QPATHINFO:
		return trans2_qpathinfo(req, trans);
	case TRANSACT2_QFILEINFO:
		return trans2_qfileinfo(req, trans);
	case TRANSACT2_SETFILEINFO:
		return trans2_setfileinfo(req, trans);
	case TRANSACT2_SETPATHINFO:
		return trans2_setpathinfo(req, trans);
	case TRANSACT2_QFSINFO:
		return trans2_qfsinfo(req, trans);
	}

	/* an unknown trans2 command */
	return NT_STATUS_FOOBAR;
}


/*
  backend for trans requests
*/
static NTSTATUS trans_backend(struct smbsrv_request *req, struct smb_trans2 *trans)
{
	if (!req->tcon->ntvfs_ops->trans) {
		return NT_STATUS_NOT_IMPLEMENTED;
	}
	return req->tcon->ntvfs_ops->trans(req, trans);
}


/****************************************************************************
 Reply to an SMBtrans or SMBtrans2 request
****************************************************************************/
void reply_trans_generic(struct smbsrv_request *req, uint8_t command)
{
	struct smb_trans2 trans;
	int i;
	uint16_t param_ofs, data_ofs;
	uint16_t param_count, data_count;
	uint16_t params_left, data_left;
	uint16_t param_total, data_total;
	char *params, *data;
	NTSTATUS status;

	/* parse request */
	if (req->in.wct < 14) {
		req_reply_error(req, NT_STATUS_FOOBAR);
		return;
	}

	param_total          = SVAL(req->in.vwv, VWV(0));
	data_total           = SVAL(req->in.vwv, VWV(1));
	trans.in.max_param   = SVAL(req->in.vwv, VWV(2));
	trans.in.max_data    = SVAL(req->in.vwv, VWV(3));
	trans.in.max_setup   = CVAL(req->in.vwv, VWV(4));
	trans.in.flags       = SVAL(req->in.vwv, VWV(5));
	trans.in.timeout     = IVAL(req->in.vwv, VWV(6));
	param_count          = SVAL(req->in.vwv, VWV(9));
	param_ofs            = SVAL(req->in.vwv, VWV(10));
	data_count           = SVAL(req->in.vwv, VWV(11));
	data_ofs             = SVAL(req->in.vwv, VWV(12));
	trans.in.setup_count = CVAL(req->in.vwv, VWV(13));

	if (req->in.wct != 14 + trans.in.setup_count) {
		req_reply_dos_error(req, ERRSRV, ERRerror);
		return;
	}

	/* parse out the setup words */
	trans.in.setup = talloc(req, trans.in.setup_count * sizeof(uint16_t));
	if (trans.in.setup_count && !trans.in.setup) {
		req_reply_error(req, NT_STATUS_NO_MEMORY);
		return;
	}
	for (i=0;i<trans.in.setup_count;i++) {
		trans.in.setup[i] = SVAL(req->in.vwv, VWV(14+i));
	}

	if (command == SMBtrans) {
		req_pull_string(req, &trans.in.trans_name, req->in.data, -1, STR_TERMINATE);
	}

	if (!req_pull_blob(req, req->in.hdr + param_ofs, param_count, &trans.in.params) ||
	    !req_pull_blob(req, req->in.hdr + data_ofs, data_count, &trans.in.data)) {
		req_reply_error(req, NT_STATUS_FOOBAR);
		return;
	}

	/* is it a partial request? if so, then send a 'send more' message */
	if (param_total > param_count ||
	    data_total > data_count) {
		DEBUG(0,("REWRITE: not handling partial trans requests!\n"));
		return;
	}

	/* its a full request, give it to the backend */
	if (command == SMBtrans) {
		status = trans_backend(req, &trans);
	} else {
		status = trans2_backend(req, &trans);
	}

	if (NT_STATUS_IS_ERR(status)) {
		req_reply_error(req, status);
		return;
	}

	params_left = trans.out.params.length;
	data_left   = trans.out.data.length;
	params      = trans.out.params.data;
	data        = trans.out.data.data;

	req->control_flags |= REQ_CONTROL_PROTECTED;

	/* we need to divide up the reply into chunks that fit into
	   the negotiated buffer size */
	do {
		uint16_t this_data, this_param, max_bytes;
		uint_t align1 = 1, align2 = (params_left ? 2 : 0);

		req_setup_reply(req, 10 + trans.out.setup_count, 0);

		if (!NT_STATUS_IS_OK(status)) {
			req_setup_error(req, status);
		}
	
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

		req_grow_data(req, this_param + this_data + (align1 + align2));

		SSVAL(req->out.vwv, VWV(0), trans.out.params.length);
		SSVAL(req->out.vwv, VWV(1), trans.out.data.length);
		SSVAL(req->out.vwv, VWV(2), 0);

		SSVAL(req->out.vwv, VWV(3), this_param);
		SSVAL(req->out.vwv, VWV(4), align1 + PTR_DIFF(req->out.data, req->out.hdr));
		SSVAL(req->out.vwv, VWV(5), PTR_DIFF(params, trans.out.params.data));

		SSVAL(req->out.vwv, VWV(6), this_data);
		SSVAL(req->out.vwv, VWV(7), align1 + align2 + 
		      PTR_DIFF(req->out.data + this_param, req->out.hdr));
		SSVAL(req->out.vwv, VWV(8), PTR_DIFF(data, trans.out.data.data));

		SSVAL(req->out.vwv, VWV(9), trans.out.setup_count);
		for (i=0;i<trans.out.setup_count;i++) {
			SSVAL(req->out.vwv, VWV(10+i), trans.out.setup[i]);
		}

		memset(req->out.data, 0, align1);
		if (this_param != 0) {
			memcpy(req->out.data + align1, params, this_param);
		}
		memset(req->out.data+this_param+align1, 0, align2);
		if (this_data != 0) {
			memcpy(req->out.data+this_param+align1+align2, data, this_data);
		}

		params_left -= this_param;
		data_left -= this_data;
		params += this_param;
		data += this_data;

		/* if this is the last chunk then the request can be destroyed */
		if (params_left == 0 && data_left == 0) {
			req->control_flags &= ~REQ_CONTROL_PROTECTED;
		}

		req_send_reply(req);
	} while (params_left != 0 || data_left != 0);
}


/****************************************************************************
 Reply to an SMBtrans2
****************************************************************************/
void reply_trans2(struct smbsrv_request *req)
{
	reply_trans_generic(req, SMBtrans2);
}

/****************************************************************************
 Reply to an SMBtrans
****************************************************************************/
void reply_trans(struct smbsrv_request *req)
{
	reply_trans_generic(req, SMBtrans);
}

/****************************************************************************
 Reply to an SMBtranss2 request
****************************************************************************/
void reply_transs2(struct smbsrv_request *req)
{
	req_reply_error(req, NT_STATUS_FOOBAR);
}


