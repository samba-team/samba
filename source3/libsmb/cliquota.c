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
	int sid_len;
	SMB_NTQUOTA_STRUCT qt;

	ZERO_STRUCT(qt);

	if (!rdata||!offset||!pqt) {
		smb_panic("parse_quota_record: called with NULL POINTER!");
	}

	if (rdata_count < 40) {
		return False;
	}

	/* offset to next quota record.
	 * 4 bytes IVAL(rdata,0)
	 * unused here...
	 */
	*offset = IVAL(rdata,0);

	/* sid len */
	sid_len = IVAL(rdata,4);
	if (40 + sid_len < 40) {
		return false;
	}

	if (rdata_count < 40+sid_len) {
		return False;		
	}

	if (*offset != 0 && *offset < 40 + sid_len) {
		return false;
	}

	/* unknown 8 bytes in pdata 
	 * maybe its the change time in NTTIME
	 */

	/* the used space 8 bytes (uint64_t)*/
	qt.usedspace = BVAL(rdata,16);

	/* the soft quotas 8 bytes (uint64_t)*/
	qt.softlim = BVAL(rdata,24);

	/* the hard quotas 8 bytes (uint64_t)*/
	qt.hardlim = BVAL(rdata,32);

	if (!sid_parse(rdata+40,sid_len,&qt.sid)) {
		return false;
	}

	qt.qtype = SMB_USER_QUOTA_TYPE;

	*pqt = qt;

	return True;
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
	uint32_t qt_len = 0;
	uint8_t *entry;
	uint32_t entry_len;
	int sid_len;
	SMB_NTQUOTA_LIST *qtl;
	DATA_BLOB qbuf = data_blob_null;
	NTSTATUS status = NT_STATUS_UNSUCCESSFUL;

	if (qt_list == NULL) {
		status = NT_STATUS_OK;
		*outbuf = data_blob_null;
		if (end_ptr) {
			*end_ptr = NULL;
		}
		return NT_STATUS_OK;
	}

	for (qtl = qt_list; qtl != NULL; qtl = qtl->next) {

		sid_len = ndr_size_dom_sid(&qtl->quotas->sid, 0);
		if (47 + sid_len < 47) {
			status = NT_STATUS_INVALID_PARAMETER;
			goto fail;
		}
		entry_len = 40 + sid_len;
		entry_len = ((entry_len + 7) / 8) * 8;

		if (qt_len + entry_len < qt_len) {
			status = NT_STATUS_INVALID_PARAMETER;
			goto fail;
		}
		qt_len += entry_len;
	}

	if (maxlen > 0 && qt_len > maxlen) {
		qt_len = maxlen;
	}

	qbuf = data_blob_talloc_zero(mem_ctx, qt_len);
	if (qbuf.data == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}

	for (qt_len = 0, entry = qbuf.data; qt_list != NULL;
	     qt_list = qt_list->next, qt_len += entry_len, entry += entry_len) {

		sid_len = ndr_size_dom_sid(&qt_list->quotas->sid, 0);
		entry_len = 40 + sid_len;
		entry_len = ((entry_len + 7) / 8) * 8;

		if (qt_len + entry_len > qbuf.length) {
			/* check for not-enough room even for a single
			 * entry
			 */
			if (qt_len == 0) {
				status = NT_STATUS_BUFFER_TOO_SMALL;
				goto fail;
			}

			break;
		}

		/* nextoffset entry 4 bytes */
		SIVAL(entry, 0, entry_len);

		/* then the len of the SID 4 bytes */
		SIVAL(entry, 4, sid_len);

		/* NTTIME of last record change */
		SBIG_UINT(entry, 8, (uint64_t)0);

		/* the used disk space 8 bytes uint64_t */
		SBIG_UINT(entry, 16, qt_list->quotas->usedspace);

		/* the soft quotas 8 bytes uint64_t */
		SBIG_UINT(entry, 24, qt_list->quotas->softlim);

		/* the hard quotas 8 bytes uint64_t */
		SBIG_UINT(entry, 32, qt_list->quotas->hardlim);

		/* and now the SID */
		sid_linearize((uint8_t *)(entry + 40), sid_len,
			      &qt_list->quotas->sid);
	}

	/* overwrite the offset of the last entry */
	SIVAL(entry - entry_len, 0, 0);

	/*potentially shrink the buffer if max was given
	 * and we haven't quite reached the max
	 */
	qbuf.length = qt_len;
	*outbuf = qbuf;
	qbuf = data_blob_null;
	status = NT_STATUS_OK;

	if (end_ptr) {
		*end_ptr = qt_list;
	}

fail:
	data_blob_free(&qbuf);

	return status;
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
	uint8_t params[16];
	unsigned int data_len;
	uint8_t data[SID_MAX_SIZE+8];
	uint8_t *rparam, *rdata;
	uint32_t rparam_count, rdata_count;
	unsigned int sid_len;
	unsigned int offset;
	NTSTATUS status;

	if (!cli||!pqt) {
		smb_panic("cli_get_user_quota() called with NULL Pointer!");
	}

	if (smbXcli_conn_protocol(cli->conn) >= PROTOCOL_SMB2_02) {
		return cli_smb2_get_user_quota(cli, quota_fnum, pqt);
	}

	SSVAL(setup + 0, 0, NT_TRANSACT_GET_USER_QUOTA);

	SSVAL(params, 0,quota_fnum);
	SSVAL(params, 2,TRANSACT_GET_USER_QUOTA_FOR_SID);
	SIVAL(params, 4,0x00000024);
	SIVAL(params, 8,0x00000000);
	SIVAL(params,12,0x00000024);

	sid_len = ndr_size_dom_sid(&pqt->sid, 0);
	data_len = sid_len+8;
	SIVAL(data, 0, 0x00000000);
	SIVAL(data, 4, sid_len);
	sid_linearize(data+8, sid_len, &pqt->sid);

	status = cli_trans(talloc_tos(), cli, SMBnttrans,
			   NULL, -1, /* name, fid */
			   NT_TRANSACT_GET_USER_QUOTA, 0,
			   setup, 1, 0, /* setup */
			   params, 16, 4, /* params */
			   data, data_len, 112, /* data */
			   NULL,		/* recv_flags2 */
			   NULL, 0, NULL,	/* rsetup */
			   &rparam, 4, &rparam_count,
			   &rdata, 8, &rdata_count);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("NT_TRANSACT_GET_USER_QUOTA failed: %s\n",
			  nt_errstr(status)));
		return status;
	}

	if (!parse_user_quota_record(rdata, rdata_count, &offset, pqt)) {
		status = NT_STATUS_INVALID_NETWORK_RESPONSE;
		DEBUG(0,("Got INVALID NT_TRANSACT_GET_USER_QUOTA reply.\n"));
	}

	TALLOC_FREE(rparam);
	TALLOC_FREE(rdata);
	return status;
}

NTSTATUS
cli_set_user_quota(struct cli_state *cli, int quota_fnum, SMB_NTQUOTA_LIST *qtl)
{
	uint16_t setup[1];
	uint8_t params[2];
	DATA_BLOB data = data_blob_null;
	NTSTATUS status = NT_STATUS_UNSUCCESSFUL;

	if (!cli || !qtl) {
		smb_panic("cli_set_user_quota() called with NULL Pointer!");
	}

	if (smbXcli_conn_protocol(cli->conn) >= PROTOCOL_SMB2_02) {
		return cli_smb2_set_user_quota(cli, quota_fnum, qtl);
	}

	status = build_user_quota_buffer(qtl, 0, talloc_tos(), &data, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		goto cleanup;
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
	uint8_t params[16];
	uint8_t *rparam=NULL, *rdata=NULL;
	uint32_t rparam_count=0, rdata_count=0;
	NTSTATUS status;
	uint16_t op = first ? TRANSACT_GET_USER_QUOTA_LIST_START
			    : TRANSACT_GET_USER_QUOTA_LIST_CONTINUE;

	if (smbXcli_conn_protocol(cli->conn) >= PROTOCOL_SMB2_02) {
		return cli_smb2_list_user_quota_step(cli, mem_ctx, quota_fnum,
						     pqt_list, first);
	}

	SSVAL(setup + 0, 0, NT_TRANSACT_GET_USER_QUOTA);

	SSVAL(params, 0,quota_fnum);
	SSVAL(params, 2, op);
	SIVAL(params, 4,0x00000000);
	SIVAL(params, 8,0x00000000);
	SIVAL(params,12,0x00000000);

	status = cli_trans(talloc_tos(), cli, SMBnttrans,
			   NULL, -1, /* name, fid */
			   NT_TRANSACT_GET_USER_QUOTA, 0,
			   setup, 1, 0, /* setup */
			   params, 16, 4, /* params */
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
