/*
   Unix SMB/CIFS implementation.
   Core SMB2 server

   Copyright (C) Stefan Metzmacher 2009

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "includes.h"
#include "smbd/globals.h"
#include "../source4/libcli/smb2/smb2_constants.h"

static NTSTATUS smbd_smb2_create(struct smbd_smb2_request *req,
				 uint8_t in_oplock_level,
				 uint32_t in_impersonation_level,
				 uint32_t in_desired_access,
				 uint32_t in_file_attributes,
				 uint32_t in_share_access,
				 uint32_t in_create_disposition,
				 uint32_t in_create_options,
				 const char *in_name,
				 uint8_t *out_oplock_level,
				 uint32_t *out_create_action,
				 NTTIME *out_creation_time,
				 NTTIME *out_last_access_time,
				 NTTIME *out_last_write_time,
				 NTTIME *out_change_time,
				 uint64_t *out_allocation_size,
				 uint64_t *out_end_of_file,
				 uint32_t *out_file_attributes,
				 uint64_t *out_file_id_volatile);

NTSTATUS smbd_smb2_request_process_create(struct smbd_smb2_request *req)
{
	const uint8_t *inbody;
	int i = req->current_idx;
	uint8_t *outhdr;
	DATA_BLOB outbody;
	DATA_BLOB outdyn;
	size_t expected_body_size = 0x39;
	size_t body_size;
	uint8_t in_oplock_level;
	uint32_t in_impersonation_level;
	uint32_t in_desired_access;
	uint32_t in_file_attributes;
	uint32_t in_share_access;
	uint32_t in_create_disposition;
	uint32_t in_create_options;
	uint16_t in_name_offset;
	uint16_t in_name_length;
	DATA_BLOB in_name_buffer;
	char *in_name_string;
	size_t in_name_string_size;
	uint8_t out_oplock_level;
	uint32_t out_create_action;
	NTTIME out_creation_time;
	NTTIME out_last_access_time;
	NTTIME out_last_write_time;
	NTTIME out_change_time;
	uint64_t out_allocation_size;
	uint64_t out_end_of_file;
	uint32_t out_file_attributes;
	uint64_t out_file_id_volatile;
	NTSTATUS status;
	bool ok;

	if (req->in.vector[i+1].iov_len != (expected_body_size & 0xFFFFFFFE)) {
		return smbd_smb2_request_error(req, NT_STATUS_INVALID_PARAMETER);
	}

	inbody = (const uint8_t *)req->in.vector[i+1].iov_base;

	body_size = SVAL(inbody, 0x00);
	if (body_size != expected_body_size) {
		return smbd_smb2_request_error(req, NT_STATUS_INVALID_PARAMETER);
	}

	in_oplock_level		= CVAL(inbody, 0x03);
	in_impersonation_level	= IVAL(inbody, 0x04);
	in_desired_access	= IVAL(inbody, 0x18);
	in_file_attributes	= IVAL(inbody, 0x1C);
	in_share_access		= IVAL(inbody, 0x20);
	in_create_disposition	= IVAL(inbody, 0x24);
	in_create_options	= IVAL(inbody, 0x28);
	in_name_offset		= SVAL(inbody, 0x2C);
	in_name_length		= SVAL(inbody, 0x2E);

	if (in_name_offset != (SMB2_HDR_BODY + (body_size & 0xFFFFFFFE))) {
		return smbd_smb2_request_error(req, NT_STATUS_INVALID_PARAMETER);
	}

	if (in_name_length > req->in.vector[i+2].iov_len) {
		return smbd_smb2_request_error(req, NT_STATUS_INVALID_PARAMETER);
	}

	in_name_buffer.data = (uint8_t *)req->in.vector[i+2].iov_base;
	in_name_buffer.length = in_name_length;

	ok = convert_string_talloc(req, CH_UTF16, CH_UNIX,
				   in_name_buffer.data,
				   in_name_buffer.length,
				   &in_name_string,
				   &in_name_string_size, false);
	if (!ok) {
		return smbd_smb2_request_error(req, NT_STATUS_ILLEGAL_CHARACTER);
	}

	status = smbd_smb2_create(req,
				  in_oplock_level,
				  in_impersonation_level,
				  in_desired_access,
				  in_file_attributes,
				  in_share_access,
				  in_create_disposition,
				  in_create_options,
				  in_name_string,
				  &out_oplock_level,
				  &out_create_action,
				  &out_creation_time,
				  &out_last_access_time,
				  &out_last_write_time,
				  &out_change_time,
				  &out_allocation_size,
				  &out_end_of_file,
				  &out_file_attributes,
				  &out_file_id_volatile);
	if (!NT_STATUS_IS_OK(status)) {
		return smbd_smb2_request_error(req, status);
	}

	outhdr = (uint8_t *)req->out.vector[i].iov_base;

	outbody = data_blob_talloc(req->out.vector, NULL, 0x58);
	if (outbody.data == NULL) {
		return smbd_smb2_request_error(req, NT_STATUS_NO_MEMORY);
	}

	SSVAL(outbody.data, 0x00, 0x58 + 1);	/* struct size */
	SCVAL(outbody.data, 0x02,
	      out_oplock_level);		/* oplock level */
	SCVAL(outbody.data, 0x03, 0);		/* reserved */
	SIVAL(outbody.data, 0x04,
	      out_create_action);		/* create action */
	SBVAL(outbody.data, 0x08,
	      out_creation_time);		/* creation time */
	SBVAL(outbody.data, 0x10,
	      out_last_access_time);		/* last access time */
	SBVAL(outbody.data, 0x18,
	      out_last_write_time);		/* last write time */
	SBVAL(outbody.data, 0x20,
	      out_change_time);			/* change time */
	SBVAL(outbody.data, 0x28,
	      out_allocation_size);		/* allocation size */
	SBVAL(outbody.data, 0x30,
	      out_end_of_file);			/* end of file */
	SIVAL(outbody.data, 0x38,
	      out_file_attributes);		/* file attributes */
	SIVAL(outbody.data, 0x3C, 0);		/* reserved */
	SBVAL(outbody.data, 0x40, 0);		/* file id (persistent) */
	SBVAL(outbody.data, 0x48,
	      out_file_id_volatile);		/* file id (volatile) */
	SIVAL(outbody.data, 0x50, 0);		/* create contexts offset */
	SIVAL(outbody.data, 0x54, 0);		/* create contexts length */

	outdyn = data_blob_const(NULL, 0);

	return smbd_smb2_request_done(req, outbody, &outdyn);
}

static NTSTATUS smbd_smb2_create(struct smbd_smb2_request *req,
				 uint8_t in_oplock_level,
				 uint32_t in_impersonation_level,
				 uint32_t in_desired_access,
				 uint32_t in_file_attributes,
				 uint32_t in_share_access,
				 uint32_t in_create_disposition,
				 uint32_t in_create_options,
				 const char *in_name,
				 uint8_t *out_oplock_level,
				 uint32_t *out_create_action,
				 NTTIME *out_creation_time,
				 NTTIME *out_last_access_time,
				 NTTIME *out_last_write_time,
				 NTTIME *out_change_time,
				 uint64_t *out_allocation_size,
				 uint64_t *out_end_of_file,
				 uint32_t *out_file_attributes,
				 uint64_t *out_file_id_volatile)
{
	NTSTATUS status;
	struct smb_request *smbreq;
	files_struct *result;
	int info;
	SMB_STRUCT_STAT sbuf;

	DEBUG(10,("smbd_smb2_create: name[%s]\n",
		  in_name));

	smbreq = smbd_smb2_fake_smb_request(req);
	if (smbreq == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	/* If it's an IPC, pass off the pipe handler. */
	if (IS_IPC(req->tcon->compat_conn)) {
		return NT_STATUS_NOT_IMPLEMENTED;
	}

	if (CAN_PRINT(req->tcon->compat_conn)) {
		return NT_STATUS_NOT_IMPLEMENTED;
	}

	switch (in_oplock_level) {
	case SMB2_OPLOCK_LEVEL_BATCH:
		break;
	case SMB2_OPLOCK_LEVEL_EXCLUSIVE:
		break;
	default:
		break;
	}

	status = SMB_VFS_CREATE_FILE(req->tcon->compat_conn,
				     smbreq,
				     0, /* root_dir_fid */
				     in_name,
				     CFF_DOS_PATH, /* create_file_flags */
				     in_desired_access,
				     in_share_access,
				     in_create_disposition,
				     in_create_options,
				     in_file_attributes,
				     0, /* oplock_request */
				     0, /* allocation_size */
				     NULL, /* security_descriptor */
				     NULL, /* ea_list */
				     &result,
				     &info,
				     &sbuf);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	*out_oplock_level	= 0;
	if ((in_create_disposition == FILE_SUPERSEDE)
	    && (info == FILE_WAS_OVERWRITTEN)) {
		*out_create_action = FILE_WAS_SUPERSEDED;
	} else {
		*out_create_action = info;
	}
	unix_timespec_to_nt_time(out_creation_time, sbuf.st_ex_btime);
	unix_timespec_to_nt_time(out_last_access_time, sbuf.st_ex_atime);
	unix_timespec_to_nt_time(out_last_write_time,sbuf.st_ex_mtime);
	unix_timespec_to_nt_time(out_change_time, sbuf.st_ex_ctime);
	*out_allocation_size	= sbuf.st_ex_blksize * sbuf.st_ex_blocks;
	*out_end_of_file	= sbuf.st_ex_size;
	*out_file_attributes	= dos_mode(result->conn,result->fsp_name,&sbuf);
	if (*out_file_attributes == 0) {
		*out_file_attributes = FILE_ATTRIBUTE_NORMAL;
	}
	*out_file_id_volatile = result->fnum;
	return NT_STATUS_OK;
}
