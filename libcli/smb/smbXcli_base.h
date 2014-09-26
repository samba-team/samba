/*
   Unix SMB/CIFS implementation.
   Infrastructure for async SMB client requests
   Copyright (C) Volker Lendecke 2008
   Copyright (C) Stefan Metzmacher 2011

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

#ifndef _SMBXCLI_BASE_H_
#define _SMBXCLI_BASE_H_

struct smbXcli_conn;
struct smbXcli_session;
struct smbXcli_tcon;
struct smb_trans_enc_state;
struct GUID;
struct iovec;
struct smb2_create_blobs;
struct smb_create_returns;

struct smbXcli_conn *smbXcli_conn_create(TALLOC_CTX *mem_ctx,
					 int fd,
					 const char *remote_name,
					 enum smb_signing_setting signing_state,
					 uint32_t smb1_capabilities,
					 struct GUID *client_guid,
					 uint32_t smb2_capabilities);

bool smbXcli_conn_is_connected(struct smbXcli_conn *conn);
void smbXcli_conn_disconnect(struct smbXcli_conn *conn, NTSTATUS status);

bool smbXcli_conn_has_async_calls(struct smbXcli_conn *conn);

bool smbXcli_conn_dfs_supported(struct smbXcli_conn *conn);

enum protocol_types smbXcli_conn_protocol(struct smbXcli_conn *conn);
bool smbXcli_conn_use_unicode(struct smbXcli_conn *conn);

void smbXcli_conn_set_sockopt(struct smbXcli_conn *conn, const char *options);
const struct sockaddr_storage *smbXcli_conn_local_sockaddr(struct smbXcli_conn *conn);
const struct sockaddr_storage *smbXcli_conn_remote_sockaddr(struct smbXcli_conn *conn);
const char *smbXcli_conn_remote_name(struct smbXcli_conn *conn);

uint16_t smbXcli_conn_max_requests(struct smbXcli_conn *conn);
NTTIME smbXcli_conn_server_system_time(struct smbXcli_conn *conn);
const DATA_BLOB *smbXcli_conn_server_gss_blob(struct smbXcli_conn *conn);
const struct GUID *smbXcli_conn_server_guid(struct smbXcli_conn *conn);

struct tevent_req *smbXcli_conn_samba_suicide_send(TALLOC_CTX *mem_ctx,
						   struct tevent_context *ev,
						   struct smbXcli_conn *conn,
						   uint8_t exitcode);
NTSTATUS smbXcli_conn_samba_suicide_recv(struct tevent_req *req);
NTSTATUS smbXcli_conn_samba_suicide(struct smbXcli_conn *conn,
				    uint8_t exitcode);

void smbXcli_req_unset_pending(struct tevent_req *req);
bool smbXcli_req_set_pending(struct tevent_req *req);

uint32_t smb1cli_conn_capabilities(struct smbXcli_conn *conn);
uint32_t smb1cli_conn_max_xmit(struct smbXcli_conn *conn);
bool smb1cli_conn_req_possible(struct smbXcli_conn *conn);
uint32_t smb1cli_conn_server_session_key(struct smbXcli_conn *conn);
const uint8_t *smb1cli_conn_server_challenge(struct smbXcli_conn *conn);
uint16_t smb1cli_conn_server_security_mode(struct smbXcli_conn *conn);
bool smb1cli_conn_server_readbraw(struct smbXcli_conn *conn);
bool smb1cli_conn_server_writebraw(struct smbXcli_conn *conn);
bool smb1cli_conn_server_lockread(struct smbXcli_conn *conn);
bool smb1cli_conn_server_writeunlock(struct smbXcli_conn *conn);
int smb1cli_conn_server_time_zone(struct smbXcli_conn *conn);

bool smb1cli_conn_activate_signing(struct smbXcli_conn *conn,
				   const DATA_BLOB user_session_key,
				   const DATA_BLOB response);
bool smb1cli_conn_check_signing(struct smbXcli_conn *conn,
				const uint8_t *buf, uint32_t seqnum);
bool smb1cli_conn_signing_is_active(struct smbXcli_conn *conn);

void smb1cli_conn_set_encryption(struct smbXcli_conn *conn,
				 struct smb_trans_enc_state *es);
bool smb1cli_conn_encryption_on(struct smbXcli_conn *conn);

bool smb1cli_is_andx_req(uint8_t cmd);
size_t smb1cli_req_wct_ofs(struct tevent_req **reqs, int num_reqs);

uint16_t smb1cli_req_mid(struct tevent_req *req);
void smb1cli_req_set_mid(struct tevent_req *req, uint16_t mid);

uint32_t smb1cli_req_seqnum(struct tevent_req *req);
void smb1cli_req_set_seqnum(struct tevent_req *req, uint32_t seqnum);

struct smb1cli_req_expected_response {
	NTSTATUS status;
	uint8_t wct;
};

struct tevent_req *smb1cli_req_create(TALLOC_CTX *mem_ctx,
				      struct tevent_context *ev,
				      struct smbXcli_conn *conn,
				      uint8_t smb_command,
				      uint8_t additional_flags,
				      uint8_t clear_flags,
				      uint16_t additional_flags2,
				      uint16_t clear_flags2,
				      uint32_t timeout_msec,
				      uint32_t pid,
				      struct smbXcli_tcon *tcon,
				      struct smbXcli_session *session,
				      uint8_t wct, uint16_t *vwv,
				      int iov_count,
				      struct iovec *bytes_iov);
NTSTATUS smb1cli_req_chain_submit(struct tevent_req **reqs, int num_reqs);

struct tevent_req *smb1cli_req_send(TALLOC_CTX *mem_ctx,
				    struct tevent_context *ev,
				    struct smbXcli_conn *conn,
				    uint8_t smb_command,
				    uint8_t additional_flags,
				    uint8_t clear_flags,
				    uint16_t additional_flags2,
				    uint16_t clear_flags2,
				    uint32_t timeout_msec,
				    uint32_t pid,
				    struct smbXcli_tcon *tcon,
				    struct smbXcli_session *session,
				    uint8_t wct, uint16_t *vwv,
				    uint32_t num_bytes,
				    const uint8_t *bytes);
NTSTATUS smb1cli_req_recv(struct tevent_req *req,
			  TALLOC_CTX *mem_ctx,
			  struct iovec **piov,
			  uint8_t **phdr,
			  uint8_t *pwct,
			  uint16_t **pvwv,
			  uint32_t *pvwv_offset,
			  uint32_t *pnum_bytes,
			  uint8_t **pbytes,
			  uint32_t *pbytes_offset,
			  uint8_t **pinbuf,
			  const struct smb1cli_req_expected_response *expected,
			  size_t num_expected);

struct tevent_req *smb1cli_trans_send(
	TALLOC_CTX *mem_ctx, struct tevent_context *ev,
	struct smbXcli_conn *conn, uint8_t cmd,
	uint8_t additional_flags, uint8_t clear_flags,
	uint16_t additional_flags2, uint16_t clear_flags2,
	uint32_t timeout_msec,
	uint32_t pid,
	struct smbXcli_tcon *tcon,
	struct smbXcli_session *session,
	const char *pipe_name, uint16_t fid, uint16_t function, int flags,
	uint16_t *setup, uint8_t num_setup, uint8_t max_setup,
	uint8_t *param, uint32_t num_param, uint32_t max_param,
	uint8_t *data, uint32_t num_data, uint32_t max_data);
NTSTATUS smb1cli_trans_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
			    uint16_t *recv_flags2,
			    uint16_t **setup, uint8_t min_setup,
			    uint8_t *num_setup,
			    uint8_t **param, uint32_t min_param,
			    uint32_t *num_param,
			    uint8_t **data, uint32_t min_data,
			    uint32_t *num_data);
NTSTATUS smb1cli_trans(TALLOC_CTX *mem_ctx, struct smbXcli_conn *conn,
		uint8_t trans_cmd,
		uint8_t additional_flags, uint8_t clear_flags,
		uint16_t additional_flags2, uint16_t clear_flags2,
		uint32_t timeout_msec,
		uint32_t pid,
		struct smbXcli_tcon *tcon,
		struct smbXcli_session *session,
		const char *pipe_name, uint16_t fid, uint16_t function,
		int flags,
		uint16_t *setup, uint8_t num_setup, uint8_t max_setup,
		uint8_t *param, uint32_t num_param, uint32_t max_param,
		uint8_t *data, uint32_t num_data, uint32_t max_data,
		uint16_t *recv_flags2,
		uint16_t **rsetup, uint8_t min_rsetup, uint8_t *num_rsetup,
		uint8_t **rparam, uint32_t min_rparam, uint32_t *num_rparam,
		uint8_t **rdata, uint32_t min_rdata, uint32_t *num_rdata);

struct tevent_req *smb1cli_echo_send(TALLOC_CTX *mem_ctx,
				     struct tevent_context *ev,
				     struct smbXcli_conn *conn,
				     uint32_t timeout_msec,
				     uint16_t num_echos,
				     DATA_BLOB data);
NTSTATUS smb1cli_echo_recv(struct tevent_req *req);
NTSTATUS smb1cli_echo(struct smbXcli_conn *conn, uint32_t timeout_msec,
		      uint16_t num_echos, DATA_BLOB data);

struct tevent_req *smb1cli_ntcreatex_send(TALLOC_CTX *mem_ctx,
					  struct tevent_context *ev,
					  struct smbXcli_conn *conn,
					  uint32_t timeout_msec,
					  uint32_t pid,
					  struct smbXcli_tcon *tcon,
					  struct smbXcli_session *session,
					  const char *fname,
					  uint32_t CreatFlags,
					  uint32_t RootDirectoryFid,
					  uint32_t DesiredAccess,
					  uint64_t AllocationSize,
					  uint32_t FileAttributes,
					  uint32_t ShareAccess,
					  uint32_t CreateDisposition,
					  uint32_t CreateOptions,
					  uint32_t ImpersonationLevel,
					  uint8_t SecurityFlags);
NTSTATUS smb1cli_ntcreatex_recv(struct tevent_req *req, uint16_t *pfnum);
NTSTATUS smb1cli_ntcreatex(struct smbXcli_conn *conn,
			   uint32_t timeout_msec,
			   uint32_t pid,
			   struct smbXcli_tcon *tcon,
			   struct smbXcli_session *session,
			   const char *fname,
			   uint32_t CreatFlags,
			   uint32_t RootDirectoryFid,
			   uint32_t DesiredAccess,
			   uint64_t AllocationSize,
			   uint32_t FileAttributes,
			   uint32_t ShareAccess,
			   uint32_t CreateDisposition,
			   uint32_t CreateOptions,
			   uint32_t ImpersonationLevel,
			   uint8_t SecurityFlags,
			   uint16_t *pfnum);
struct tevent_req *smb1cli_close_send(TALLOC_CTX *mem_ctx,
				      struct tevent_context *ev,
				      struct smbXcli_conn *conn,
				      uint32_t timeout_msec,
				      uint32_t pid,
				      struct smbXcli_tcon *tcon,
				      struct smbXcli_session *session,
				      uint16_t fnum,
				      uint32_t last_modified);
NTSTATUS smb1cli_close_recv(struct tevent_req *req);
NTSTATUS smb1cli_close(struct smbXcli_conn *conn,
		       uint32_t timeout_msec,
		       uint32_t pid,
		       struct smbXcli_tcon *tcon,
		       struct smbXcli_session *session,
		       uint16_t fnum,
		       uint32_t last_modified);
struct tevent_req *smb1cli_writex_send(TALLOC_CTX *mem_ctx,
				       struct tevent_context *ev,
				       struct smbXcli_conn *conn,
				       uint32_t timeout_msec,
				       uint32_t pid,
				       struct smbXcli_tcon *tcon,
				       struct smbXcli_session *session,
				       uint16_t fnum,
				       uint16_t mode,
				       const uint8_t *buf,
				       uint64_t offset,
				       uint32_t size);
NTSTATUS smb1cli_writex_recv(struct tevent_req *req,
			     uint32_t *pwritten,
			     uint16_t *pavailable);
NTSTATUS smb1cli_writex(struct smbXcli_conn *conn,
			uint32_t timeout_msec,
			uint32_t pid,
			struct smbXcli_tcon *tcon,
			struct smbXcli_session *session,
			uint16_t fnum,
			uint16_t mode,
			const uint8_t *buf,
			uint64_t offset,
			uint32_t size,
			uint32_t *pwritten,
			uint16_t *pavailable);
struct tevent_req *smb1cli_readx_send(TALLOC_CTX *mem_ctx,
				      struct tevent_context *ev,
				      struct smbXcli_conn *conn,
				      uint32_t timeout_msec,
				      uint32_t pid,
				      struct smbXcli_tcon *tcon,
				      struct smbXcli_session *session,
				      uint16_t fnum,
				      uint64_t offset,
				      uint32_t size);
NTSTATUS smb1cli_readx_recv(struct tevent_req *req,
			    uint32_t *received,
			    uint8_t **rcvbuf);

bool smb2cli_conn_req_possible(struct smbXcli_conn *conn, uint32_t *max_dyn_len);
uint32_t smb2cli_conn_server_capabilities(struct smbXcli_conn *conn);
uint16_t smb2cli_conn_server_security_mode(struct smbXcli_conn *conn);
uint32_t smb2cli_conn_max_trans_size(struct smbXcli_conn *conn);
uint32_t smb2cli_conn_max_read_size(struct smbXcli_conn *conn);
uint32_t smb2cli_conn_max_write_size(struct smbXcli_conn *conn);
void smb2cli_conn_set_max_credits(struct smbXcli_conn *conn,
				  uint16_t max_credits);

struct tevent_req *smb2cli_req_create(TALLOC_CTX *mem_ctx,
				      struct tevent_context *ev,
				      struct smbXcli_conn *conn,
				      uint16_t cmd,
				      uint32_t additional_flags,
				      uint32_t clear_flags,
				      uint32_t timeout_msec,
				      struct smbXcli_tcon *tcon,
				      struct smbXcli_session *session,
				      const uint8_t *fixed,
				      uint16_t fixed_len,
				      const uint8_t *dyn,
				      uint32_t dyn_len,
				      uint32_t max_dyn_len);
void smb2cli_req_set_notify_async(struct tevent_req *req);
NTSTATUS smb2cli_req_compound_submit(struct tevent_req **reqs,
				     int num_reqs);
void smb2cli_req_set_credit_charge(struct tevent_req *req, uint16_t charge);

struct smb2cli_req_expected_response {
	NTSTATUS status;
	uint16_t body_size;
};

struct tevent_req *smb2cli_req_send(TALLOC_CTX *mem_ctx,
				    struct tevent_context *ev,
				    struct smbXcli_conn *conn,
				    uint16_t cmd,
				    uint32_t additional_flags,
				    uint32_t clear_flags,
				    uint32_t timeout_msec,
				    struct smbXcli_tcon *tcon,
				    struct smbXcli_session *session,
				    const uint8_t *fixed,
				    uint16_t fixed_len,
				    const uint8_t *dyn,
				    uint32_t dyn_len,
				    uint32_t max_dyn_len);
NTSTATUS smb2cli_req_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
			  struct iovec **piov,
			  const struct smb2cli_req_expected_response *expected,
			  size_t num_expected);

struct tevent_req *smbXcli_negprot_send(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct smbXcli_conn *conn,
					uint32_t timeout_msec,
					enum protocol_types min_protocol,
					enum protocol_types max_protocol);
NTSTATUS smbXcli_negprot_recv(struct tevent_req *req);
NTSTATUS smbXcli_negprot(struct smbXcli_conn *conn,
			 uint32_t timeout_msec,
			 enum protocol_types min_protocol,
			 enum protocol_types max_protocol);

struct tevent_req *smb2cli_validate_negotiate_info_send(TALLOC_CTX *mem_ctx,
						struct tevent_context *ev,
						struct smbXcli_conn *conn,
						uint32_t timeout_msec,
						struct smbXcli_session *session,
						struct smbXcli_tcon *tcon);
NTSTATUS smb2cli_validate_negotiate_info_recv(struct tevent_req *req);

struct smbXcli_session *smbXcli_session_create(TALLOC_CTX *mem_ctx,
					       struct smbXcli_conn *conn);
struct smbXcli_session *smbXcli_session_copy(TALLOC_CTX *mem_ctx,
					       struct smbXcli_session *src);
bool smbXcli_session_is_authenticated(struct smbXcli_session *session);
NTSTATUS smbXcli_session_application_key(struct smbXcli_session *session,
					 TALLOC_CTX *mem_ctx,
					 DATA_BLOB *key);
void smbXcli_session_set_disconnect_expired(struct smbXcli_session *session);
uint16_t smb1cli_session_current_id(struct smbXcli_session* session);
void smb1cli_session_set_id(struct smbXcli_session* session,
			    uint16_t session_id);
NTSTATUS smb1cli_session_set_session_key(struct smbXcli_session *session,
					 const DATA_BLOB _session_key);
NTSTATUS smb1cli_session_protect_session_key(struct smbXcli_session *session);
uint8_t smb2cli_session_security_mode(struct smbXcli_session *session);
uint64_t smb2cli_session_current_id(struct smbXcli_session *session);
uint16_t smb2cli_session_get_flags(struct smbXcli_session *session);
void smb2cli_session_set_id_and_flags(struct smbXcli_session *session,
				      uint64_t session_id,
				      uint16_t session_flags);
void smb2cli_session_increment_channel_sequence(struct smbXcli_session *session);
uint16_t smb2cli_session_reset_channel_sequence(struct smbXcli_session *session,
						uint16_t channel_sequence);
void smb2cli_session_start_replay(struct smbXcli_session *session);
void smb2cli_session_stop_replay(struct smbXcli_session *session);
NTSTATUS smb2cli_session_set_session_key(struct smbXcli_session *session,
					 const DATA_BLOB session_key,
					 const struct iovec *recv_iov);
NTSTATUS smb2cli_session_create_channel(TALLOC_CTX *mem_ctx,
					struct smbXcli_session *session1,
					struct smbXcli_conn *conn,
					struct smbXcli_session **_session2);
NTSTATUS smb2cli_session_set_channel_key(struct smbXcli_session *session,
					 const DATA_BLOB channel_key,
					 const struct iovec *recv_iov);
NTSTATUS smb2cli_session_encryption_on(struct smbXcli_session *session);

struct smbXcli_tcon *smbXcli_tcon_create(TALLOC_CTX *mem_ctx);
void smbXcli_tcon_set_fs_attributes(struct smbXcli_tcon *tcon,
				    uint32_t fs_attributes);
uint32_t smbXcli_tcon_get_fs_attributes(struct smbXcli_tcon *tcon);
bool smbXcli_tcon_is_dfs_share(struct smbXcli_tcon *tcon);
uint16_t smb1cli_tcon_current_id(struct smbXcli_tcon *tcon);
void smb1cli_tcon_set_id(struct smbXcli_tcon *tcon, uint16_t tcon_id);
bool smb1cli_tcon_set_values(struct smbXcli_tcon *tcon,
			     uint16_t tcon_id,
			     uint16_t optional_support,
			     uint32_t maximal_access,
			     uint32_t guest_maximal_access,
			     const char *service,
			     const char *fs_type);
uint32_t smb2cli_tcon_current_id(struct smbXcli_tcon *tcon);
uint32_t smb2cli_tcon_capabilities(struct smbXcli_tcon *tcon);
void smb2cli_tcon_set_values(struct smbXcli_tcon *tcon,
			     struct smbXcli_session *session,
			     uint32_t tcon_id,
			     uint8_t type,
			     uint32_t flags,
			     uint32_t capabilities,
			     uint32_t maximal_access);
void smb2cli_tcon_should_sign(struct smbXcli_tcon *tcon,
			      bool should_sign);
bool smb2cli_tcon_is_signing_on(struct smbXcli_tcon *tcon);
void smb2cli_tcon_should_encrypt(struct smbXcli_tcon *tcon,
				 bool should_encrypt);
bool smb2cli_tcon_is_encryption_on(struct smbXcli_tcon *tcon);

struct tevent_req *smb2cli_session_setup_send(TALLOC_CTX *mem_ctx,
				struct tevent_context *ev,
				struct smbXcli_conn *conn,
				uint32_t timeout_msec,
				struct smbXcli_session *session,
				uint8_t in_flags,
				uint32_t in_capabilities,
				uint32_t in_channel,
				uint64_t in_previous_session_id,
				const DATA_BLOB *in_security_buffer);
NTSTATUS smb2cli_session_setup_recv(struct tevent_req *req,
				    TALLOC_CTX *mem_ctx,
				    struct iovec **recv_iov,
				    DATA_BLOB *out_security_buffer);

struct tevent_req *smb2cli_logoff_send(TALLOC_CTX *mem_ctx,
				       struct tevent_context *ev,
				       struct smbXcli_conn *conn,
				       uint32_t timeout_msec,
				       struct smbXcli_session *session);
NTSTATUS smb2cli_logoff_recv(struct tevent_req *req);
NTSTATUS smb2cli_logoff(struct smbXcli_conn *conn,
			uint32_t timeout_msec,
			struct smbXcli_session *session);

struct tevent_req *smb2cli_tcon_send(TALLOC_CTX *mem_ctx,
				     struct tevent_context *ev,
				     struct smbXcli_conn *conn,
				     uint32_t timeout_msec,
				     struct smbXcli_session *session,
				     struct smbXcli_tcon *tcon,
				     uint16_t flags,
				     const char *unc);
NTSTATUS smb2cli_tcon_recv(struct tevent_req *req);
NTSTATUS smb2cli_tcon(struct smbXcli_conn *conn,
		      uint32_t timeout_msec,
		      struct smbXcli_session *session,
		      struct smbXcli_tcon *tcon,
		      uint16_t flags,
		      const char *unc);

struct tevent_req *smb2cli_tdis_send(TALLOC_CTX *mem_ctx,
				     struct tevent_context *ev,
				     struct smbXcli_conn *conn,
				     uint32_t timeout_msec,
				     struct smbXcli_session *session,
				     struct smbXcli_tcon *tcon);
NTSTATUS smb2cli_tdis_recv(struct tevent_req *req);
NTSTATUS smb2cli_tdis(struct smbXcli_conn *conn,
		      uint32_t timeout_msec,
		      struct smbXcli_session *session,
		      struct smbXcli_tcon *tcon);

struct tevent_req *smb2cli_create_send(
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	struct smbXcli_conn *conn,
	uint32_t timeout_msec,
	struct smbXcli_session *session,
	struct smbXcli_tcon *tcon,
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
			     uint64_t *fid_volatile,
			     struct smb_create_returns *cr,
			     TALLOC_CTX *mem_ctx,
			     struct smb2_create_blobs *blobs);
NTSTATUS smb2cli_create(struct smbXcli_conn *conn,
			uint32_t timeout_msec,
			struct smbXcli_session *session,
			struct smbXcli_tcon *tcon,
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
			uint64_t *fid_volatile,
			struct smb_create_returns *cr,
			TALLOC_CTX *mem_ctx,
			struct smb2_create_blobs *ret_blobs);

struct tevent_req *smb2cli_close_send(TALLOC_CTX *mem_ctx,
				      struct tevent_context *ev,
				      struct smbXcli_conn *conn,
				      uint32_t timeout_msec,
				      struct smbXcli_session *session,
				      struct smbXcli_tcon *tcon,
				      uint16_t flags,
				      uint64_t fid_persistent,
				      uint64_t fid_volatile);
NTSTATUS smb2cli_close_recv(struct tevent_req *req);
NTSTATUS smb2cli_close(struct smbXcli_conn *conn,
		       uint32_t timeout_msec,
		       struct smbXcli_session *session,
		       struct smbXcli_tcon *tcon,
		       uint16_t flags,
		       uint64_t fid_persistent,
		       uint64_t fid_volatile);

struct tevent_req *smb2cli_read_send(TALLOC_CTX *mem_ctx,
				     struct tevent_context *ev,
				     struct smbXcli_conn *conn,
				     uint32_t timeout_msec,
				     struct smbXcli_session *session,
				     struct smbXcli_tcon *tcon,
				     uint32_t length,
				     uint64_t offset,
				     uint64_t fid_persistent,
				     uint64_t fid_volatile,
				     uint64_t minimum_count,
				     uint64_t remaining_bytes);
NTSTATUS smb2cli_read_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
			   uint8_t **data, uint32_t *data_length);
NTSTATUS smb2cli_read(struct smbXcli_conn *conn,
		      uint32_t timeout_msec,
		      struct smbXcli_session *session,
		      struct smbXcli_tcon *tcon,
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
				      struct smbXcli_conn *conn,
				      uint32_t timeout_msec,
				      struct smbXcli_session *session,
				      struct smbXcli_tcon *tcon,
				      uint32_t length,
				      uint64_t offset,
				      uint64_t fid_persistent,
				      uint64_t fid_volatile,
				      uint32_t remaining_bytes,
				      uint32_t flags,
				      const uint8_t *data);
NTSTATUS smb2cli_write_recv(struct tevent_req *req,
			uint32_t *written);
NTSTATUS smb2cli_write(struct smbXcli_conn *conn,
		       uint32_t timeout_msec,
		       struct smbXcli_session *session,
		       struct smbXcli_tcon *tcon,
		       uint32_t length,
		       uint64_t offset,
		       uint64_t fid_persistent,
		       uint64_t fid_volatile,
		       uint32_t remaining_bytes,
		       uint32_t flags,
		       const uint8_t *data,
		       uint32_t *written);

struct tevent_req *smb2cli_flush_send(TALLOC_CTX *mem_ctx,
				      struct tevent_context *ev,
				      struct smbXcli_conn *conn,
				      uint32_t timeout_msec,
				      struct smbXcli_session *session,
				      struct smbXcli_tcon *tcon,
				      uint64_t fid_persistent,
				      uint64_t fid_volatile);
NTSTATUS smb2cli_flush_recv(struct tevent_req *req);
NTSTATUS smb2cli_flush(struct smbXcli_conn *conn,
		       uint32_t timeout_msec,
		       struct smbXcli_session *session,
		       struct smbXcli_tcon *tcon,
		       uint64_t fid_persistent,
		       uint64_t fid_volatile);

struct tevent_req *smb2cli_set_info_send(TALLOC_CTX *mem_ctx,
					 struct tevent_context *ev,
					 struct smbXcli_conn *conn,
					 uint32_t timeout_msec,
					 struct smbXcli_session *session,
					 struct smbXcli_tcon *tcon,
					 uint8_t in_info_type,
					 uint8_t in_file_info_class,
					 const DATA_BLOB *in_input_buffer,
					 uint32_t in_additional_info,
					 uint64_t in_fid_persistent,
					 uint64_t in_fid_volatile);
NTSTATUS smb2cli_set_info_recv(struct tevent_req *req);
NTSTATUS smb2cli_set_info(struct smbXcli_conn *conn,
			  uint32_t timeout_msec,
			  struct smbXcli_session *session,
			  struct smbXcli_tcon *tcon,
			  uint8_t in_info_type,
			  uint8_t in_file_info_class,
			  const DATA_BLOB *in_input_buffer,
			  uint32_t in_additional_info,
			  uint64_t in_fid_persistent,
			  uint64_t in_fid_volatile);

struct tevent_req *smb2cli_query_info_send(TALLOC_CTX *mem_ctx,
					   struct tevent_context *ev,
					   struct smbXcli_conn *conn,
					   uint32_t timeout_msec,
					   struct smbXcli_session *session,
					   struct smbXcli_tcon *tcon,
					   uint8_t in_info_type,
					   uint8_t in_file_info_class,
					   uint32_t in_max_output_length,
					   const DATA_BLOB *in_input_buffer,
					   uint32_t in_additional_info,
					   uint32_t in_flags,
					   uint64_t in_fid_persistent,
					   uint64_t in_fid_volatile);
NTSTATUS smb2cli_query_info_recv(struct tevent_req *req,
				 TALLOC_CTX *mem_ctx,
				 DATA_BLOB *out_output_buffer);
NTSTATUS smb2cli_query_info(struct smbXcli_conn *conn,
			    uint32_t timeout_msec,
			    struct smbXcli_session *session,
			    struct smbXcli_tcon *tcon,
			    uint8_t in_info_type,
			    uint8_t in_file_info_class,
			    uint32_t in_max_output_length,
			    const DATA_BLOB *in_input_buffer,
			    uint32_t in_additional_info,
			    uint32_t in_flags,
			    uint64_t in_fid_persistent,
			    uint64_t in_fid_volatile,
			    TALLOC_CTX *mem_ctx,
			    DATA_BLOB *out_output_buffer);

struct tevent_req *smb2cli_query_directory_send(TALLOC_CTX *mem_ctx,
						struct tevent_context *ev,
						struct smbXcli_conn *conn,
						uint32_t timeout_msec,
						struct smbXcli_session *session,
						struct smbXcli_tcon *tcon,
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
NTSTATUS smb2cli_query_directory(struct smbXcli_conn *conn,
				 uint32_t timeout_msec,
				 struct smbXcli_session *session,
				 struct smbXcli_tcon *tcon,
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

struct tevent_req *smb2cli_ioctl_send(TALLOC_CTX *mem_ctx,
				      struct tevent_context *ev,
				      struct smbXcli_conn *conn,
				      uint32_t timeout_msec,
				      struct smbXcli_session *session,
				      struct smbXcli_tcon *tcon,
				      uint64_t in_fid_persistent,
				      uint64_t in_fid_volatile,
				      uint32_t in_ctl_code,
				      uint32_t in_max_input_length,
				      const DATA_BLOB *in_input_buffer,
				      uint32_t in_max_output_length,
				      const DATA_BLOB *in_output_buffer,
				      uint32_t in_flags);
NTSTATUS smb2cli_ioctl_recv(struct tevent_req *req,
			    TALLOC_CTX *mem_ctx,
			    DATA_BLOB *out_input_buffer,
			    DATA_BLOB *out_output_buffer);
NTSTATUS smb2cli_ioctl(struct smbXcli_conn *conn,
		       uint32_t timeout_msec,
		       struct smbXcli_session *session,
		       struct smbXcli_tcon *tcon,
		       uint64_t in_fid_persistent,
		       uint64_t in_fid_volatile,
		       uint32_t in_ctl_code,
		       uint32_t in_max_input_length,
		       const DATA_BLOB *in_input_buffer,
		       uint32_t in_max_output_length,
		       const DATA_BLOB *in_output_buffer,
		       uint32_t in_flags,
		       TALLOC_CTX *mem_ctx,
		       DATA_BLOB *out_input_buffer,
		       DATA_BLOB *out_output_buffer);

struct tevent_req *smb2cli_echo_send(TALLOC_CTX *mem_ctx,
				     struct tevent_context *ev,
				     struct smbXcli_conn *conn,
				     uint32_t timeout_msec);
NTSTATUS smb2cli_echo_recv(struct tevent_req *req);
NTSTATUS smb2cli_echo(struct smbXcli_conn *conn,
		      uint32_t timeout_msec);

#endif /* _SMBXCLI_BASE_H_ */
