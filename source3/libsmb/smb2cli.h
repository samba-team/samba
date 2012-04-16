/*
   Unix SMB/CIFS implementation.
   smb2 client routines
   Copyright (C) Volker Lendecke 2011

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

#ifndef __SMB2CLI_H__
#define __SMB2CLI_H__

struct smbXcli_conn;
struct smbXcli_session;
struct cli_state;

struct tevent_req *smb2cli_logoff_send(TALLOC_CTX *mem_ctx,
				       struct tevent_context *ev,
				       struct cli_state *cli);
NTSTATUS smb2cli_logoff_recv(struct tevent_req *req);
NTSTATUS smb2cli_logoff(struct cli_state *cli);

struct tevent_req *smb2cli_tcon_send(TALLOC_CTX *mem_ctx,
				     struct tevent_context *ev,
				     struct cli_state *cli,
				     const char *share);
NTSTATUS smb2cli_tcon_recv(struct tevent_req *req);
NTSTATUS smb2cli_tcon(struct cli_state *cli, const char *share);

struct tevent_req *smb2cli_tdis_send(TALLOC_CTX *mem_ctx,
				     struct tevent_context *ev,
				     struct cli_state *cli);
NTSTATUS smb2cli_tdis_recv(struct tevent_req *req);
NTSTATUS smb2cli_tdis(struct cli_state *cli);

struct tevent_req *smb2cli_create_send(
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	struct cli_state *cli,
	const char *filename,
	uint8_t  oplock_level,		/* SMB2_OPLOCK_LEVEL_* */
	uint32_t impersonation_level,	/* SMB2_IMPERSONATION_* */
	uint32_t desired_access,
	uint32_t file_attributes,
	uint32_t share_access,
	uint32_t create_disposition,
	uint32_t create_options,
	struct smb2_create_blobs *blobs);
NTSTATUS smb2cli_create_recv(struct tevent_req *req,
			     uint64_t *fid_persistent,
			     uint64_t *fid_volatile);
NTSTATUS smb2cli_create(struct cli_state *cli,
			const char *filename,
			uint8_t  oplock_level,	     /* SMB2_OPLOCK_LEVEL_* */
			uint32_t impersonation_level, /* SMB2_IMPERSONATION_* */
			uint32_t desired_access,
			uint32_t file_attributes,
			uint32_t share_access,
			uint32_t create_disposition,
			uint32_t create_options,
			struct smb2_create_blobs *blobs,
			uint64_t *fid_persistent,
			uint64_t *fid_volatile);

struct tevent_req *smb2cli_close_send(TALLOC_CTX *mem_ctx,
				      struct tevent_context *ev,
				      struct cli_state *cli,
				      uint16_t flags,
				      uint64_t fid_persistent,
				      uint64_t fid_volatile);
NTSTATUS smb2cli_close_recv(struct tevent_req *req);
NTSTATUS smb2cli_close(struct cli_state *cli, uint16_t flags,
			uint64_t fid_persistent, uint64_t fid_volatile);

struct tevent_req *smb2cli_flush_send(TALLOC_CTX *mem_ctx,
				      struct tevent_context *ev,
				      struct cli_state *cli,
				      uint64_t fid_persistent,
				      uint64_t fid_volatile);
NTSTATUS smb2cli_flush_recv(struct tevent_req *req);
NTSTATUS smb2cli_flush(struct cli_state *cli,
		       uint64_t fid_persistent,
		       uint64_t fid_volatile);

struct tevent_req *smb2cli_read_send(TALLOC_CTX *mem_ctx,
				     struct tevent_context *ev,
				     struct cli_state *cli,
				     uint32_t length,
				     uint64_t offset,
				     uint64_t fid_persistent,
				     uint64_t fid_volatile,
				     uint64_t minimum_count,
				     uint64_t remaining_bytes);
NTSTATUS smb2cli_read_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
			   uint8_t **data, uint32_t *data_length);
NTSTATUS smb2cli_read(struct cli_state *cli,
		      uint32_t length,
		      uint64_t offset,
		      uint64_t fid_persistent,
		      uint64_t fid_volatile,
		      uint64_t minimum_count,
		      uint64_t remaining_bytes,
		      TALLOC_CTX *mem_ctx,
		      uint8_t **data,
		      uint32_t *data_length);

struct tevent_req *smb2cli_write_send(TALLOC_CTX *mem_ctx,
				      struct tevent_context *ev,
				      struct cli_state *cli,
				      uint32_t length,
				      uint64_t offset,
				      uint64_t fid_persistent,
				      uint64_t fid_volatile,
				      uint32_t remaining_bytes,
				      uint32_t flags,
				      const uint8_t *data);
NTSTATUS smb2cli_write_recv(struct tevent_req *req);
NTSTATUS smb2cli_write(struct cli_state *cli,
		       uint32_t length,
		       uint64_t offset,
		       uint64_t fid_persistent,
		       uint64_t fid_volatile,
		       uint32_t remaining_bytes,
		       uint32_t flags,
		       const uint8_t *data);

struct tevent_req *smb2cli_query_directory_send(TALLOC_CTX *mem_ctx,
						struct tevent_context *ev,
						struct cli_state *cli,
						uint8_t level,
						uint8_t flags,
						uint32_t file_index,
						uint64_t fid_persistent,
						uint64_t fid_volatile,
						const char *mask,
						uint32_t outbuf_len);
NTSTATUS smb2cli_query_directory_recv(struct tevent_req *req,
				      TALLOC_CTX *mem_ctx,
				      uint8_t **data,
				      uint32_t *data_length);
NTSTATUS smb2cli_query_directory(struct cli_state *cli,
				 uint8_t level,
				 uint8_t flags,
				 uint32_t file_index,
				 uint64_t fid_persistent,
				 uint64_t fid_volatile,
				 const char *mask,
				 uint32_t outbuf_len,
				 TALLOC_CTX *mem_ctx,
				 uint8_t **data,
				 uint32_t *data_length);

#endif /* __SMB2CLI_H__ */
