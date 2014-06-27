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

struct tevent_req *cli_smb2_create_fnum_send(TALLOC_CTX *mem_ctx,
					     struct tevent_context *ev,
					     struct cli_state *cli,
					     const char *fname,
					     uint32_t create_flags,
					     uint32_t desired_access,
					     uint32_t file_attributes,
					     uint32_t share_access,
					     uint32_t create_disposition,
					     uint32_t create_options);
NTSTATUS cli_smb2_create_fnum_recv(struct tevent_req *req, uint16_t *pfnum,
				   struct smb_create_returns *cr);
NTSTATUS cli_smb2_create_fnum(struct cli_state *cli,
			const char *fname,
			uint32_t create_flags,
			uint32_t desired_access,
			uint32_t file_attributes,
			uint32_t share_access,
			uint32_t create_disposition,
			uint32_t create_options,
			uint16_t *pfid,
			struct smb_create_returns *cr);

struct tevent_req *cli_smb2_close_fnum_send(TALLOC_CTX *mem_ctx,
					    struct tevent_context *ev,
					    struct cli_state *cli,
					    uint16_t fnum);
NTSTATUS cli_smb2_close_fnum_recv(struct tevent_req *req);
NTSTATUS cli_smb2_close_fnum(struct cli_state *cli, uint16_t fnum);
NTSTATUS cli_smb2_mkdir(struct cli_state *cli, const char *dirname);
NTSTATUS cli_smb2_rmdir(struct cli_state *cli, const char *dirname);
NTSTATUS cli_smb2_unlink(struct cli_state *cli,const char *fname);
NTSTATUS cli_smb2_list(struct cli_state *cli,
			const char *pathname,
			uint16_t attribute,
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
NTSTATUS cli_smb2_qfileinfo_basic(struct cli_state *cli,
			uint16_t fnum,
			uint16_t *mode,
			off_t *size,
			struct timespec *create_time,
			struct timespec *access_time,
			struct timespec *write_time,
			struct timespec *change_time,
			SMB_INO_T *ino);
NTSTATUS cli_smb2_getattrE(struct cli_state *cli,
			uint16_t fnum,
			uint16_t *attr,
			off_t *size,
			time_t *change_time,
			time_t *access_time,
			time_t *write_time);
NTSTATUS cli_smb2_getatr(struct cli_state *cli,
			const char *name,
			uint16_t *attr,
			off_t *size,
			time_t *write_time);
NTSTATUS cli_smb2_qpathinfo2(struct cli_state *cli,
			const char *fname,
			struct timespec *create_time,
			struct timespec *access_time,
			struct timespec *write_time,
			struct timespec *change_time,
			off_t *size,
			uint16_t *mode,
			SMB_INO_T *ino);
NTSTATUS cli_smb2_qpathinfo_streams(struct cli_state *cli,
			const char *name,
			TALLOC_CTX *mem_ctx,
			unsigned int *pnum_streams,
			struct stream_struct **pstreams);
NTSTATUS cli_smb2_setatr(struct cli_state *cli,
			const char *fname,
			uint16_t attr,
			time_t mtime);
NTSTATUS cli_smb2_setattrE(struct cli_state *cli,
                        uint16_t fnum,
                        time_t change_time,
                        time_t access_time,
                        time_t write_time);
NTSTATUS cli_smb2_dskattr(struct cli_state *cli,
			uint64_t *bsize,
			uint64_t *total,
			uint64_t *avail);
NTSTATUS cli_smb2_query_security_descriptor(struct cli_state *cli,
			uint16_t fnum,
			uint32_t sec_info,
			TALLOC_CTX *mem_ctx,
			struct security_descriptor **ppsd);
NTSTATUS cli_smb2_set_security_descriptor(struct cli_state *cli,
			uint16_t fnum,
			uint32_t sec_info,
			const struct security_descriptor *sd);
NTSTATUS cli_smb2_rename(struct cli_state *cli,
			const char *fname_src,
			const char *fname_dst);
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
#endif /* __SMB2CLI_FNUM_H__ */
