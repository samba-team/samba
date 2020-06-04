/*
   Unix SMB/CIFS implementation.
   smb2 wrapper client routines
   Copyright (C) Jeremy Allison 2013

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

#ifndef __SMB2CLI_FNUM_H__
#define __SMB2CLI_FNUM_H__

struct smbXcli_conn;
struct smbXcli_session;
struct cli_state;
struct file_info;

struct tevent_req *cli_smb2_create_fnum_send(
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	struct cli_state *cli,
	const char *fname,
	uint32_t create_flags,
	uint32_t impersonation_level,
	uint32_t desired_access,
	uint32_t file_attributes,
	uint32_t share_access,
	uint32_t create_disposition,
	uint32_t create_options,
	const struct smb2_create_blobs *in_cblobs);
NTSTATUS cli_smb2_create_fnum_recv(
	struct tevent_req *req,
	uint16_t *pfnum,
	struct smb_create_returns *cr,
	TALLOC_CTX *mem_ctx,
	struct smb2_create_blobs *out_cblobs);
NTSTATUS cli_smb2_create_fnum(
	struct cli_state *cli,
	const char *fname,
	uint32_t create_flags,
	uint32_t impersonation_level,
	uint32_t desired_access,
	uint32_t file_attributes,
	uint32_t share_access,
	uint32_t create_disposition,
	uint32_t create_options,
	const struct smb2_create_blobs *in_cblobs,
	uint16_t *pfid,
	struct smb_create_returns *cr,
	TALLOC_CTX *mem_ctx,
	struct smb2_create_blobs *out_cblobs);

struct tevent_req *cli_smb2_close_fnum_send(TALLOC_CTX *mem_ctx,
					    struct tevent_context *ev,
					    struct cli_state *cli,
					    uint16_t fnum);
NTSTATUS cli_smb2_close_fnum_recv(struct tevent_req *req);
NTSTATUS cli_smb2_close_fnum(struct cli_state *cli, uint16_t fnum);
struct tevent_req *cli_smb2_delete_on_close_send(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct cli_state *cli,
					uint16_t fnum,
					bool flag);
NTSTATUS cli_smb2_delete_on_close_recv(struct tevent_req *req);
NTSTATUS cli_smb2_delete_on_close(struct cli_state *cli, uint16_t fnum, bool flag);
struct tevent_req *cli_smb2_mkdir_send(
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	struct cli_state *cli,
	const char *name);
NTSTATUS cli_smb2_mkdir_recv(struct tevent_req *req);
struct tevent_req *cli_smb2_rmdir_send(
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	struct cli_state *cli,
	const char *dname,
	const struct smb2_create_blobs *in_cblobs);
NTSTATUS cli_smb2_rmdir_recv(struct tevent_req *req);
struct tevent_req *cli_smb2_unlink_send(
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	struct cli_state *cli,
	const char *fname,
	const struct smb2_create_blobs *in_cblobs);
NTSTATUS cli_smb2_unlink_recv(struct tevent_req *req);
NTSTATUS cli_smb2_list(struct cli_state *cli,
			const char *pathname,
			uint32_t attribute,
			NTSTATUS (*fn)(const char *,
				struct file_info *,
				const char *,
				void *),
			void *state);
NTSTATUS cli_smb2_qpathinfo_basic(struct cli_state *cli,
			const char *name,
			SMB_STRUCT_STAT *sbuf,
			uint32_t *attributes);
NTSTATUS cli_smb2_qpathinfo_alt_name(struct cli_state *cli,
			const char *name,
			fstring alt_name);
struct tevent_req *cli_smb2_chkpath_send(
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	struct cli_state *cli,
	const char *name);
NTSTATUS cli_smb2_chkpath_recv(struct tevent_req *req);
struct tevent_req *cli_smb2_query_info_fnum_send(
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	struct cli_state *cli,
	uint16_t fnum,
	uint8_t in_info_type,
	uint8_t in_info_class,
	uint32_t in_max_output_length,
	const DATA_BLOB *in_input_buffer,
	uint32_t in_additional_info,
	uint32_t in_flags);
NTSTATUS cli_smb2_query_info_fnum_recv(
	struct tevent_req *req, TALLOC_CTX *mem_ctx, DATA_BLOB *outbuf);
struct tevent_req *cli_smb2_set_info_fnum_send(
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	struct cli_state *cli,
	uint16_t fnum,
	uint8_t in_info_type,
	uint8_t in_info_class,
	const DATA_BLOB *in_input_buffer,
	uint32_t in_additional_info);
NTSTATUS cli_smb2_set_info_fnum_recv(struct tevent_req *req);
NTSTATUS cli_smb2_set_info_fnum(
	struct cli_state *cli,
	uint16_t fnum,
	uint8_t in_info_type,
	uint8_t in_info_class,
	const DATA_BLOB *in_input_buffer,
	uint32_t in_additional_info);
NTSTATUS cli_smb2_query_info_fnum(
	struct cli_state *cli,
	uint16_t fnum,
	uint8_t in_info_type,
	uint8_t in_info_class,
	uint32_t in_max_output_length,
	const DATA_BLOB *in_input_buffer,
	uint32_t in_additional_info,
	uint32_t in_flags,
	TALLOC_CTX *mem_ctx,
	DATA_BLOB *outbuf);
NTSTATUS cli_smb2_getatr(struct cli_state *cli,
			const char *name,
			uint32_t *pattr,
			off_t *size,
			time_t *write_time);
NTSTATUS cli_smb2_qpathinfo2(struct cli_state *cli,
			const char *fname,
			struct timespec *create_time,
			struct timespec *access_time,
			struct timespec *write_time,
			struct timespec *change_time,
			off_t *size,
			uint32_t *pattr,
			SMB_INO_T *ino);
NTSTATUS cli_smb2_qpathinfo_streams(struct cli_state *cli,
			const char *name,
			TALLOC_CTX *mem_ctx,
			unsigned int *pnum_streams,
			struct stream_struct **pstreams);
NTSTATUS cli_smb2_setpathinfo(struct cli_state *cli,
			const char *name,
			uint8_t in_info_type,
			uint8_t in_file_info_class,
			const DATA_BLOB *p_in_data);
NTSTATUS cli_smb2_setatr(struct cli_state *cli,
			const char *fname,
			uint32_t attr,
			time_t mtime);
NTSTATUS cli_smb2_setattrE(struct cli_state *cli,
                        uint16_t fnum,
                        time_t change_time,
                        time_t access_time,
                        time_t write_time);
NTSTATUS cli_smb2_dskattr(struct cli_state *cli,
			const char *path,
			uint64_t *bsize,
			uint64_t *total,
			uint64_t *avail);
NTSTATUS cli_smb2_get_fs_attr_info(struct cli_state *cli, uint32_t *fs_attr);
NTSTATUS cli_smb2_get_fs_full_size_info(struct cli_state *cli,
			uint64_t *total_allocation_units,
			uint64_t *caller_allocation_units,
			uint64_t *actual_allocation_units,
			uint64_t *sectors_per_allocation_unit,
			uint64_t *bytes_per_sector);
NTSTATUS cli_smb2_get_fs_volume_info(struct cli_state *cli,
			TALLOC_CTX *mem_ctx,
			char **_volume_name,
			uint32_t *pserial_number,
			time_t *pdate);
NTSTATUS cli_smb2_query_security_descriptor(struct cli_state *cli,
			uint16_t fnum,
			uint32_t sec_info,
			TALLOC_CTX *mem_ctx,
			struct security_descriptor **ppsd);
NTSTATUS cli_smb2_set_security_descriptor(struct cli_state *cli,
			uint16_t fnum,
			uint32_t sec_info,
			const struct security_descriptor *sd);
struct tevent_req *cli_smb2_query_mxac_send(TALLOC_CTX *mem_ctx,
					    struct tevent_context *ev,
					    struct cli_state *cli,
					    const char *fname);
NTSTATUS cli_smb2_query_mxac_recv(struct tevent_req *req,
				  uint32_t *mxac);
NTSTATUS cli_smb2_query_mxac(struct cli_state *cli,
			     const char *fname,
			     uint32_t *mxac);
NTSTATUS cli_smb2_rename(struct cli_state *cli,
			 const char *fname_src,
			 const char *fname_dst,
			 bool replace);
NTSTATUS cli_smb2_set_ea_fnum(struct cli_state *cli,
			uint16_t fnum,
			const char *ea_name,
			const char *ea_val,
			size_t ea_len);
NTSTATUS cli_smb2_get_ea_list_path(struct cli_state *cli,
			const char *name,
			TALLOC_CTX *ctx,
			size_t *pnum_eas,
			struct ea_struct **pea_list);
NTSTATUS cli_smb2_set_ea_path(struct cli_state *cli,
			const char *name,
			const char *ea_name,
			const char *ea_val,
			size_t ea_len);
NTSTATUS cli_smb2_get_user_quota(struct cli_state *cli,
				 int quota_fnum,
				 SMB_NTQUOTA_STRUCT *pqt);
NTSTATUS cli_smb2_list_user_quota_step(struct cli_state *cli,
				       TALLOC_CTX *mem_ctx,
				       int quota_fnum,
				       SMB_NTQUOTA_LIST **pqt_list,
				       bool first);
NTSTATUS cli_smb2_get_fs_quota_info(struct cli_state *cli,
				    int quota_fnum,
				    SMB_NTQUOTA_STRUCT *pqt);
NTSTATUS cli_smb2_set_user_quota(struct cli_state *cli,
				 int quota_fnum,
				 SMB_NTQUOTA_LIST *qtl);
NTSTATUS cli_smb2_set_fs_quota_info(struct cli_state *cli,
				    int quota_fnum,
				    SMB_NTQUOTA_STRUCT *pqt);
struct tevent_req *cli_smb2_read_send(TALLOC_CTX *mem_ctx,
				struct tevent_context *ev,
				struct cli_state *cli,
				uint16_t fnum,
				off_t offset,
				size_t size);
NTSTATUS cli_smb2_read_recv(struct tevent_req *req,
				ssize_t *received,
				uint8_t **rcvbuf);
struct tevent_req *cli_smb2_write_send(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct cli_state *cli,
					uint16_t fnum,
					uint16_t mode,
					const uint8_t *buf,
					off_t offset,
					size_t size);
NTSTATUS cli_smb2_write_recv(struct tevent_req *req,
			     size_t *pwritten);
struct tevent_req *cli_smb2_writeall_send(TALLOC_CTX *mem_ctx,
			struct tevent_context *ev,
			struct cli_state *cli,
			uint16_t fnum,
			uint16_t mode,
			const uint8_t *buf,
			off_t offset,
			size_t size);
NTSTATUS cli_smb2_writeall_recv(struct tevent_req *req,
			size_t *pwritten);
struct tevent_req *cli_smb2_splice_send(TALLOC_CTX *mem_ctx,
			struct tevent_context *ev,
			struct cli_state *cli,
			uint16_t src_fnum, uint16_t dst_fnum,
			off_t size, off_t src_offset, off_t dst_offset,
			int (*splice_cb)(off_t n, void *priv), void *priv);
NTSTATUS cli_smb2_splice_recv(struct tevent_req *req, off_t *written);
NTSTATUS cli_smb2_shadow_copy_data(TALLOC_CTX *mem_ctx,
			struct cli_state *cli,
			uint16_t fnum,
			bool get_names,
			char ***pnames,
			int *pnum_names);
NTSTATUS cli_smb2_ftruncate(struct cli_state *cli,
			uint16_t fnum,
			uint64_t newsize);
struct tevent_req *cli_smb2_notify_send(
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	struct cli_state *cli,
	uint16_t fnum,
	uint32_t buffer_size,
	uint32_t completion_filter,
	bool recursive);
NTSTATUS cli_smb2_notify_recv(struct tevent_req *req,
			      TALLOC_CTX *mem_ctx,
			      struct notify_change **pchanges,
			      uint32_t *pnum_changes);
NTSTATUS cli_smb2_notify(struct cli_state *cli, uint16_t fnum,
			 uint32_t buffer_size, uint32_t completion_filter,
			 bool recursive, TALLOC_CTX *mem_ctx,
			 struct notify_change **pchanges,
			 uint32_t *pnum_changes);
struct tevent_req *cli_smb2_set_reparse_point_fnum_send(
			TALLOC_CTX *mem_ctx,
			struct tevent_context *ev,
			struct cli_state *cli,
			uint16_t fnum,
			DATA_BLOB in_buf);
NTSTATUS cli_smb2_set_reparse_point_fnum_recv(struct tevent_req *req);

struct tevent_req *cli_smb2_get_reparse_point_fnum_send(
			TALLOC_CTX *mem_ctx,
			struct tevent_context *ev,
			struct cli_state *cli,
			uint16_t fnum);
NTSTATUS cli_smb2_get_reparse_point_fnum_recv(struct tevent_req *req,
			TALLOC_CTX *mem_ctx,
			DATA_BLOB *output);

#endif /* __SMB2CLI_FNUM_H__ */
