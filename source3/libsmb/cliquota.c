/* 
   Unix SMB/CIFS implementation.
   client quota functions
   Copyright (C) Stefan (metze) Metzmacher	2003

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
#include "libsmb/libsmb.h"
#include "../librpc/gen_ndr/ndr_security.h"
#include "fake_file.h"
#include "../libcli/security/security.h"
#include "trans2.h"
#include "../libcli/smb/smbXcli_base.h"
#include "librpc/gen_ndr/ndr_quota.h"

NTSTATUS cli_get_quota_handle(struct cli_state *cli, uint16_t *quota_fnum)
{
	return cli_ntcreate(cli, FAKE_FILE_NAME_QUOTA_WIN32,
		 0x00000016, DESIRED_ACCESS_PIPE,
		 0x00000000, FILE_SHARE_READ|FILE_SHARE_WRITE,
		 FILE_OPEN, 0x00000000, 0x03, quota_fnum, NULL);
}

void free_ntquota_list(SMB_NTQUOTA_LIST **qt_list)
{
	if (!qt_list || !*qt_list) {
		return;
	}

	if ((*qt_list)->mem_ctx)
		talloc_destroy((*qt_list)->mem_ctx);

	(*qt_list) = NULL;

	return;	
}

bool add_record_to_ntquota_list(TALLOC_CTX *mem_ctx,
				SMB_NTQUOTA_STRUCT *pqt,
				SMB_NTQUOTA_LIST **pqt_list)
{
	SMB_NTQUOTA_LIST *tmp_list_ent;

	if ((tmp_list_ent = talloc_zero(mem_ctx, SMB_NTQUOTA_LIST)) == NULL) {
		return false;
	}

	if ((tmp_list_ent->quotas = talloc_zero(mem_ctx, SMB_NTQUOTA_STRUCT)) ==
	    NULL) {
		return false;
	}

	*tmp_list_ent->quotas = *pqt;
	tmp_list_ent->mem_ctx = mem_ctx;

	DLIST_ADD((*pqt_list), tmp_list_ent);

	return true;
}

bool parse_user_quota_record(const uint8_t *rdata,
			     unsigned int rdata_count,
			     unsigned int *offset,
			     SMB_NTQUOTA_STRUCT *pqt)
{
	struct file_quota_information info = {0};
	TALLOC_CTX *frame = talloc_stackframe();
	DATA_BLOB blob;
	enum ndr_err_code err;
	bool result = false;

	blob.data = discard_const_p(uint8_t, rdata);
	blob.length = rdata_count;
	err = ndr_pull_struct_blob(
			&blob,
			frame,
			&info,
			(ndr_pull_flags_fn_t)ndr_pull_file_quota_information);

	if (!NDR_ERR_CODE_IS_SUCCESS(err)) {
		goto out;
	}

	*offset = info.next_entry_offset;

	ZERO_STRUCTP(pqt);
	pqt->usedspace = info.quota_used;

	pqt->softlim = info.quota_threshold;

	pqt->hardlim = info.quota_limit;

	pqt->qtype = SMB_USER_QUOTA_TYPE;
	pqt->sid = info.sid;
	result = true;
out:
	TALLOC_FREE(frame);
	return result;
}

NTSTATUS parse_user_quota_list(const uint8_t *curdata,
			       uint32_t curdata_count,
			       TALLOC_CTX *mem_ctx,
			       SMB_NTQUOTA_LIST **pqt_list)
{
	NTSTATUS status = NT_STATUS_OK;
	unsigned offset;
	SMB_NTQUOTA_STRUCT qt;

	while (true) {
		ZERO_STRUCT(qt);
		if (!parse_user_quota_record(curdata, curdata_count, &offset,
					     &qt)) {
			DEBUG(1, ("Failed to parse the quota record\n"));
			status = NT_STATUS_INVALID_NETWORK_RESPONSE;
			break;
		}

		if (offset > curdata_count) {
			DEBUG(1, ("out of bounds offset in quota record\n"));
			status = NT_STATUS_INVALID_NETWORK_RESPONSE;
			break;
		}

		if (curdata + offset < curdata) {
			DEBUG(1, ("Pointer overflow in quota record\n"));
			status = NT_STATUS_INVALID_NETWORK_RESPONSE;
			break;
		}

		if (!add_record_to_ntquota_list(mem_ctx, &qt, pqt_list)) {
			status = NT_STATUS_NO_MEMORY;
			break;
		}

		curdata += offset;
		curdata_count -= offset;

		if (offset == 0) {
			break;
		}
	}

	return status;
}

NTSTATUS parse_fs_quota_buffer(const uint8_t *rdata,
			       unsigned int rdata_count,
			       SMB_NTQUOTA_STRUCT *pqt)
{
	SMB_NTQUOTA_STRUCT qt;

	ZERO_STRUCT(qt);

	if (rdata_count < 48) {
		/* minimum length is not enforced by SMB2 client.
		 */
		DEBUG(1, ("small returned fs quota buffer\n"));
		return NT_STATUS_INVALID_NETWORK_RESPONSE;
	}

	/* unknown_1 24 NULL bytes in pdata*/

	/* the soft quotas 8 bytes (uint64_t)*/
	qt.softlim = BVAL(rdata, 24);

	/* the hard quotas 8 bytes (uint64_t)*/
	qt.hardlim = BVAL(rdata, 32);

	/* quota_flags 2 bytes **/
	qt.qflags = SVAL(rdata, 40);

	qt.qtype = SMB_USER_FS_QUOTA_TYPE;

	*pqt = qt;

	return NT_STATUS_OK;
}

NTSTATUS build_user_quota_buffer(SMB_NTQUOTA_LIST *qt_list,
				 uint32_t maxlen,
				 TALLOC_CTX *mem_ctx,
				 DATA_BLOB *outbuf,
				 SMB_NTQUOTA_LIST **end_ptr)
{
	return fill_quota_buffer(mem_ctx,
				 qt_list,
				 false,
				 maxlen,
				 outbuf,
				 end_ptr);
}

NTSTATUS build_fs_quota_buffer(TALLOC_CTX *mem_ctx,
			       const SMB_NTQUOTA_STRUCT *pqt,
			       DATA_BLOB *blob,
			       uint32_t maxlen)
{
	uint8_t *buf;

	if (maxlen > 0 && maxlen < 48) {
		return NT_STATUS_BUFFER_TOO_SMALL;
	}

	*blob = data_blob_talloc_zero(mem_ctx, 48);

	if (!blob->data) {
		return NT_STATUS_NO_MEMORY;
	}

	buf = blob->data;

	/* Unknown1 24 NULL bytes*/
	SBIG_UINT(buf, 0, (uint64_t)0);
	SBIG_UINT(buf, 8, (uint64_t)0);
	SBIG_UINT(buf, 16, (uint64_t)0);

	/* Default Soft Quota 8 bytes */
	SBIG_UINT(buf, 24, pqt->softlim);

	/* Default Hard Quota 8 bytes */
	SBIG_UINT(buf, 32, pqt->hardlim);

	/* Quota flag 4 bytes */
	SIVAL(buf, 40, pqt->qflags);

	/* 4 padding bytes */
	SIVAL(buf, 44, 0);

	return NT_STATUS_OK;
}

NTSTATUS cli_get_user_quota(struct cli_state *cli, int quota_fnum,
			    SMB_NTQUOTA_STRUCT *pqt)
{
	uint16_t setup[1];
	uint8_t *rparam = NULL, *rdata = NULL;
	uint32_t rparam_count, rdata_count;
	unsigned int sid_len;
	unsigned int offset;
	struct nttrans_query_quota_params get_quota = {0};
	struct file_get_quota_info info =  {0};
	enum ndr_err_code err;
	NTSTATUS status;
	TALLOC_CTX *frame = talloc_stackframe();
	DATA_BLOB data_blob = data_blob_null;
	DATA_BLOB param_blob = data_blob_null;

	if (!cli||!pqt) {
		smb_panic("cli_get_user_quota() called with NULL Pointer!");
	}

	if (smbXcli_conn_protocol(cli->conn) >= PROTOCOL_SMB2_02) {
		TALLOC_FREE(frame);
		return cli_smb2_get_user_quota(cli, quota_fnum, pqt);
	}

	get_quota.fid = quota_fnum;
	get_quota.return_single_entry = 1;
	get_quota.restart_scan = 0;

	sid_len = ndr_size_dom_sid(&pqt->sid, 0);

	info.next_entry_offset = 0;
	info.sid_length = sid_len;
	info.sid = pqt->sid;

	err = ndr_push_struct_blob(
			&data_blob,
			frame,
			&info,
			(ndr_push_flags_fn_t)ndr_push_file_get_quota_info);

	if (!NDR_ERR_CODE_IS_SUCCESS(err)) {
		status = NT_STATUS_INTERNAL_ERROR;
		goto out;
	}

	get_quota.sid_list_length = data_blob.length;
	get_quota.start_sid_offset = data_blob.length;

	err = ndr_push_struct_blob(
		&param_blob,
		frame,
		&get_quota,
		(ndr_push_flags_fn_t)ndr_push_nttrans_query_quota_params);

	if (!NDR_ERR_CODE_IS_SUCCESS(err)) {
		status = NT_STATUS_INTERNAL_ERROR;
		goto out;
	}

	status = cli_trans(talloc_tos(), cli, SMBnttrans,
			   NULL, -1, /* name, fid */
			   NT_TRANSACT_GET_USER_QUOTA, 0,
			   setup, 1, 0, /* setup */
			   param_blob.data, param_blob.length, 4, /* params */
			   data_blob.data, data_blob.length, 112, /* data */
			   NULL,		/* recv_flags2 */
			   NULL, 0, NULL,	/* rsetup */
			   &rparam, 4, &rparam_count,
			   &rdata, 8, &rdata_count);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("NT_TRANSACT_GET_USER_QUOTA failed: %s\n",
			  nt_errstr(status)));
		goto out;
	}

	if (!parse_user_quota_record(rdata, rdata_count, &offset, pqt)) {
		status = NT_STATUS_INVALID_NETWORK_RESPONSE;
		DEBUG(0,("Got INVALID NT_TRANSACT_GET_USER_QUOTA reply.\n"));
	}

out:
	TALLOC_FREE(rparam);
	TALLOC_FREE(rdata);
	TALLOC_FREE(frame);
	return status;
}

NTSTATUS
cli_set_user_quota(struct cli_state *cli, int quota_fnum, SMB_NTQUOTA_LIST *qtl)
{
	uint16_t setup[1];
	uint8_t params[2];
	DATA_BLOB data = data_blob_null;
	NTSTATUS status;

	if (!cli || !qtl) {
		smb_panic("cli_set_user_quota() called with NULL Pointer!");
	}

	if (smbXcli_conn_protocol(cli->conn) >= PROTOCOL_SMB2_02) {
		return cli_smb2_set_user_quota(cli, quota_fnum, qtl);
	}

	status = build_user_quota_buffer(qtl, 0, talloc_tos(), &data, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		/*
		 * smb1 doesn't send NT_STATUS_NO_MORE_ENTRIES so swallow
		 * this status.
		 */
		if (!NT_STATUS_EQUAL(status, NT_STATUS_NO_MORE_ENTRIES)) {
			goto cleanup;
		}
	}

	SSVAL(setup + 0, 0, NT_TRANSACT_SET_USER_QUOTA);

	SSVAL(params,0,quota_fnum);

	status = cli_trans(talloc_tos(), cli, SMBnttrans,
			   NULL, -1, /* name, fid */
			   NT_TRANSACT_SET_USER_QUOTA, 0,
			   setup, 1, 0, /* setup */
			   params, 2, 0, /* params */
			   data.data, data.length, 0, /* data */
			   NULL,		/* recv_flags2 */
			   NULL, 0, NULL,	/* rsetup */
			   NULL, 0, NULL,	/* rparams */
			   NULL, 0, NULL);	/* rdata */

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("NT_TRANSACT_SET_USER_QUOTA failed: %s\n",
			  nt_errstr(status)));
	}

cleanup:
	data_blob_free(&data);
	return status;
}

static NTSTATUS cli_list_user_quota_step(struct cli_state *cli,
					 TALLOC_CTX *mem_ctx,
					 int quota_fnum,
					 SMB_NTQUOTA_LIST **pqt_list,
					 bool first)
{
	uint16_t setup[1];
	DATA_BLOB params_blob = data_blob_null;
	uint8_t *rparam=NULL, *rdata=NULL;
	uint32_t rparam_count=0, rdata_count=0;
	NTSTATUS status;
	struct nttrans_query_quota_params quota_params = {0};
	enum ndr_err_code err;

	TALLOC_CTX *frame = NULL;
	if (smbXcli_conn_protocol(cli->conn) >= PROTOCOL_SMB2_02) {
		return cli_smb2_list_user_quota_step(cli, mem_ctx, quota_fnum,
						     pqt_list, first);
	}
	frame = talloc_stackframe();

	SSVAL(setup + 0, 0, NT_TRANSACT_GET_USER_QUOTA);

	quota_params.fid = quota_fnum;
	if (first) {
		quota_params.restart_scan = 1;
	}
	err = ndr_push_struct_blob(
		&params_blob,
		frame,
		&quota_params,
		(ndr_push_flags_fn_t)ndr_push_nttrans_query_quota_params);

	if (!NDR_ERR_CODE_IS_SUCCESS(err)) {
		status = NT_STATUS_INVALID_PARAMETER;
		goto cleanup;
	}

	status = cli_trans(talloc_tos(), cli, SMBnttrans,
			   NULL, -1, /* name, fid */
			   NT_TRANSACT_GET_USER_QUOTA, 0,
			   setup, 1, 0, /* setup */
			   params_blob.data, params_blob.length, 4, /* params */
			   NULL, 0, 2048, /* data */
			   NULL,		/* recv_flags2 */
			   NULL, 0, NULL,	/* rsetup */
			   &rparam, 0, &rparam_count,
			   &rdata, 0, &rdata_count);

	/* compat. with smbd + safeguard against
	 * endless loop
	 */
	if (NT_STATUS_IS_OK(status) && rdata_count == 0) {
		status = NT_STATUS_NO_MORE_ENTRIES;
	}

	if (!NT_STATUS_IS_OK(status)) {
		goto cleanup;
	}

	status = parse_user_quota_list(rdata, rdata_count, mem_ctx, pqt_list);

cleanup:
	TALLOC_FREE(rparam);
	TALLOC_FREE(rdata);
	TALLOC_FREE(frame);

	return status;
}

NTSTATUS cli_list_user_quota(struct cli_state *cli,
			     int quota_fnum,
			     SMB_NTQUOTA_LIST **pqt_list)
{
	NTSTATUS status;
	TALLOC_CTX *mem_ctx = NULL;
	bool first = true;

	if (!cli || !pqt_list) {
		smb_panic("cli_list_user_quota() called with NULL Pointer!");
	}

	*pqt_list = NULL;

	if ((mem_ctx = talloc_init("SMB_USER_QUOTA_LIST")) == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	do {
		status = cli_list_user_quota_step(cli, mem_ctx, quota_fnum,
						  pqt_list, first);
		first = false;
	} while (NT_STATUS_IS_OK(status));

	if (NT_STATUS_EQUAL(status, NT_STATUS_NO_MORE_ENTRIES)) {
		status = NT_STATUS_OK;
	}

	if (!NT_STATUS_IS_OK(status) || *pqt_list == NULL) {
		TALLOC_FREE(mem_ctx);
	}

	return status;
}

NTSTATUS cli_get_fs_quota_info(struct cli_state *cli, int quota_fnum,
			       SMB_NTQUOTA_STRUCT *pqt)
{
	uint16_t setup[1];
	uint8_t param[2];
	uint8_t *rdata=NULL;
	uint32_t rdata_count=0;
	NTSTATUS status;

	if (!cli||!pqt) {
		smb_panic("cli_get_fs_quota_info() called with NULL Pointer!");
	}

	if (smbXcli_conn_protocol(cli->conn) >= PROTOCOL_SMB2_02) {
		return cli_smb2_get_fs_quota_info(cli, quota_fnum, pqt);
	}

	SSVAL(setup + 0, 0, TRANSACT2_QFSINFO);

	SSVAL(param,0,SMB_FS_QUOTA_INFORMATION);

	status = cli_trans(talloc_tos(), cli, SMBtrans2,
			   NULL, -1, /* name, fid */
			   0, 0,     /* function, flags */
			   setup, 1, 0, /* setup */
			   param, 2, 0, /* param */
			   NULL, 0, 560, /* data */
			   NULL,	 /* recv_flags2 */
			   NULL, 0, NULL, /* rsetup */
			   NULL, 0, NULL, /* rparam */
			   &rdata, 48, &rdata_count);

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("SMB_FS_QUOTA_INFORMATION failed: %s\n",
			  nt_errstr(status)));
		return status;
	}

	status = parse_fs_quota_buffer(rdata, rdata_count, pqt);

	TALLOC_FREE(rdata);
	return status;
}

NTSTATUS cli_set_fs_quota_info(struct cli_state *cli, int quota_fnum,
			       SMB_NTQUOTA_STRUCT *pqt)
{
	uint16_t setup[1];
	uint8_t param[4];
	DATA_BLOB data = data_blob_null;
	NTSTATUS status;

	if (!cli||!pqt) {
		smb_panic("cli_set_fs_quota_info() called with NULL Pointer!");
	}

	if (smbXcli_conn_protocol(cli->conn) >= PROTOCOL_SMB2_02) {
		return cli_smb2_set_fs_quota_info(cli, quota_fnum, pqt);
	}

	status = build_fs_quota_buffer(talloc_tos(), pqt, &data, 0);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	SSVAL(setup + 0, 0,TRANSACT2_SETFSINFO);

	SSVAL(param,0,quota_fnum);
	SSVAL(param,2,SMB_FS_QUOTA_INFORMATION);

	status = cli_trans(talloc_tos(), cli, SMBtrans2,
			   NULL, -1, /* name, fid */
			   0, 0,     /* function, flags */
			   setup, 1, 0, /* setup */
			   param, 4, 0, /* param */
			   data.data, data.length, 0, /* data */
			   NULL,	 /* recv_flags2 */
			   NULL, 0, NULL, /* rsetup */
			   NULL, 0, NULL, /* rparam */
			   NULL, 0, NULL); /* rdata */

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("SMB_FS_QUOTA_INFORMATION failed: %s\n",
			  nt_errstr(status)));
	}

	return status;
}

NTSTATUS fill_quota_buffer(TALLOC_CTX *mem_ctx,
			      SMB_NTQUOTA_LIST *qlist,
			      bool return_single,
			      uint32_t max_data,
			      DATA_BLOB *blob,
			      SMB_NTQUOTA_LIST **end_ptr)
{
	int ndr_flags = NDR_SCALARS | NDR_BUFFERS;
	struct ndr_push *qndr = NULL;
	uint32_t start_offset = 0;
	uint32_t padding = 0;
	if (qlist == NULL) {
		/* We must push at least one. */
		return NT_STATUS_NO_MORE_ENTRIES;
	}

	qndr = ndr_push_init_ctx(mem_ctx);
	if (qndr == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	for (;qlist != NULL; qlist = qlist->next) {
		struct file_quota_information info = {0};
		enum ndr_err_code err;
		uint32_t dsize = sizeof(info.next_entry_offset)
			+ sizeof(info.sid_length)
			+ sizeof(info.change_time)
			+ sizeof(info.quota_used)
			+ sizeof(info.quota_threshold)
			+ sizeof(info.quota_limit);


		info.sid_length = ndr_size_dom_sid(&qlist->quotas->sid, 0);

		if (max_data) {
			uint32_t curr_pos_no_padding = qndr->offset - padding;
			uint32_t payload = dsize + info.sid_length;
			uint32_t new_pos = (curr_pos_no_padding + payload);
			if (new_pos < curr_pos_no_padding) {
				/* Detect unlikely integer wrap */
				DBG_ERR("Integer wrap while adjusting pos "
					"0x%x by offset 0x%x\n",
					curr_pos_no_padding, payload);
				return NT_STATUS_INTERNAL_ERROR;
			}
			if (new_pos > max_data) {
				DBG_WARNING("Max data will be exceeded "
					    "writing next query info. "
					    "cur_pos 0x%x, sid_length 0x%x, "
					    "dsize 0x%x, max_data 0x%x\n",
					    curr_pos_no_padding,
					    info.sid_length,
					    dsize,
					    max_data);
				break;
			}
		}

		start_offset = qndr->offset;
		info.sid = qlist->quotas->sid;
		info.quota_used = qlist->quotas->usedspace;
		info.quota_threshold = qlist->quotas->softlim;
		info.quota_limit = qlist->quotas->hardlim;

		err = ndr_push_file_quota_information(qndr,
						      ndr_flags,
						      &info);

		if (!NDR_ERR_CODE_IS_SUCCESS(err)) {
			DBG_DEBUG("Failed to push the quota sid\n");
			return NT_STATUS_INTERNAL_ERROR;
		}

		/* pidl will align to 8 bytes due to 8 byte members*/
		/* Remember how much align padding we've used. */
		padding = qndr->offset;

		err = ndr_push_align(qndr, 8);
		if (!NDR_ERR_CODE_IS_SUCCESS(err)) {
			DBG_DEBUG("ndr_push_align returned %s\n",
				  ndr_map_error2string(err));
			return ndr_map_error2ntstatus(err);
		}

		padding = qndr->offset - padding;

		/*
		 * Overwrite next_entry_offset for this entry now
		 * we know what it should be. We know we're using
		 * LIBNDR_FLAG_LITTLE_ENDIAN here so we can use
		 * SIVAL.
		 */
		info.next_entry_offset = qndr->offset - start_offset;
		SIVAL(qndr->data, start_offset, info.next_entry_offset);

		if (return_single) {
			break;
		}
	}

	if (end_ptr != NULL) {
		*end_ptr = qlist;
	}

	/* Remove the padding alignment on the last element pushed. */
	blob->length = qndr->offset - padding;
	blob->data = qndr->data;

	/*
	 * Terminate the pushed array by setting next_entry_offset
	 * for the last element to zero.
	 */
	if (blob->length >= sizeof(uint32_t)) {
		SIVAL(qndr->data, start_offset, 0);
	}
	return NT_STATUS_OK;
}
