/*
 * Unix SMB/CIFS implementation.
 * collected prototypes header
 *
 * frozen from "make proto" in May 2008
 *
 * Copyright (C) Michael Adam 2008
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _CLIENT_PROTO_H_
#define _CLIENT_PROTO_H_


/* The following definitions come from client/client.c  */

const char *client_get_cur_dir(void);
const char *client_set_cur_dir(const char *newdir);
void do_list(const char *mask,
			uint16 attribute,
			void (*fn)(file_info *, const char *dir),
			bool rec,
			bool dirs);
int cmd_iosize(void);

/* The following definitions come from client/clitar.c  */

int cmd_block(void);
int cmd_tarmode(void);
int cmd_setmode(void);
int cmd_tar(void);
int process_tar(void);
int tar_parseargs(int argc, char *argv[], const char *Optarg, int Optind);

/* The following definitions come from client/dnsbrowse.c  */

int do_smb_browse(void);
int do_smb_browse(void);

/* The following definitions come from rpc_client/cli_netlogon.c  */

NTSTATUS rpccli_netlogon_setup_creds(struct rpc_pipe_client *cli,
				     const char *server_name,
				     const char *domain,
				     const char *clnt_name,
				     const char *machine_account,
				     const unsigned char machine_pwd[16],
				     enum netr_SchannelType sec_chan_type,
				     uint32_t *neg_flags_inout);
NTSTATUS rpccli_netlogon_sam_logon(struct rpc_pipe_client *cli,
				   TALLOC_CTX *mem_ctx,
				   uint32 logon_parameters,
				   const char *domain,
				   const char *username,
				   const char *password,
				   const char *workstation,
				   int logon_type);
NTSTATUS rpccli_netlogon_sam_network_logon(struct rpc_pipe_client *cli,
					   TALLOC_CTX *mem_ctx,
					   uint32 logon_parameters,
					   const char *server,
					   const char *username,
					   const char *domain,
					   const char *workstation,
					   const uint8 chal[8],
					   DATA_BLOB lm_response,
					   DATA_BLOB nt_response,
					   struct netr_SamInfo3 **info3);
NTSTATUS rpccli_netlogon_sam_network_logon_ex(struct rpc_pipe_client *cli,
					      TALLOC_CTX *mem_ctx,
					      uint32 logon_parameters,
					      const char *server,
					      const char *username,
					      const char *domain,
					      const char *workstation,
					      const uint8 chal[8],
					      DATA_BLOB lm_response,
					      DATA_BLOB nt_response,
					      struct netr_SamInfo3 **info3);

/* The following definitions come from rpc_client/cli_pipe.c  */

NTSTATUS rpc_api_pipe_req(struct rpc_pipe_client *cli,
			uint8 op_num,
			prs_struct *in_data,
			prs_struct *out_data);
NTSTATUS rpc_pipe_bind(struct rpc_pipe_client *cli,
		       struct cli_pipe_auth_data *auth);
unsigned int rpccli_set_timeout(struct rpc_pipe_client *cli,
				unsigned int timeout);
bool rpccli_is_pipe_idx(struct rpc_pipe_client *cli, int pipe_idx);
bool rpccli_get_pwd_hash(struct rpc_pipe_client *cli, uint8_t nt_hash[16]);
struct cli_state *rpc_pipe_np_smb_conn(struct rpc_pipe_client *p);
NTSTATUS rpccli_anon_bind_data(TALLOC_CTX *mem_ctx,
			       struct cli_pipe_auth_data **presult);
NTSTATUS rpccli_ntlmssp_bind_data(TALLOC_CTX *mem_ctx,
				  enum pipe_auth_type auth_type,
				  enum pipe_auth_level auth_level,
				  const char *domain,
				  const char *username,
				  const char *password,
				  struct cli_pipe_auth_data **presult);
NTSTATUS rpccli_schannel_bind_data(TALLOC_CTX *mem_ctx, const char *domain,
				   enum pipe_auth_level auth_level,
				   const uint8_t sess_key[16],
				   struct cli_pipe_auth_data **presult);
NTSTATUS rpccli_kerberos_bind_data(TALLOC_CTX *mem_ctx,
				   enum pipe_auth_level auth_level,
				   const char *service_princ,
				   const char *username,
				   const char *password,
				   struct cli_pipe_auth_data **presult);
NTSTATUS rpc_pipe_open_tcp(TALLOC_CTX *mem_ctx, const char *host,
			   const struct ndr_syntax_id *abstract_syntax,
			   struct rpc_pipe_client **presult);
struct rpc_pipe_client *cli_rpc_pipe_open_noauth(struct cli_state *cli, int pipe_idx, NTSTATUS *perr);
struct rpc_pipe_client *cli_rpc_pipe_open_ntlmssp(struct cli_state *cli,
						int pipe_idx,
						enum pipe_auth_level auth_level,
						const char *domain,
						const char *username,
						const char *password,
						NTSTATUS *perr);
struct rpc_pipe_client *cli_rpc_pipe_open_spnego_ntlmssp(struct cli_state *cli,
						int pipe_idx,
						enum pipe_auth_level auth_level,
						const char *domain,
						const char *username,
						const char *password,
						NTSTATUS *perr);
struct rpc_pipe_client *get_schannel_session_key(struct cli_state *cli,
							const char *domain,
							uint32 *pneg_flags,
							NTSTATUS *perr);
struct rpc_pipe_client *cli_rpc_pipe_open_schannel_with_key(struct cli_state *cli,
					int pipe_idx,
					enum pipe_auth_level auth_level,
					const char *domain,
					const struct dcinfo *pdc,
					NTSTATUS *perr);
struct rpc_pipe_client *cli_rpc_pipe_open_ntlmssp_auth_schannel(struct cli_state *cli,
                                                int pipe_idx,
						enum pipe_auth_level auth_level,
                                                const char *domain,
						const char *username,
						const char *password,
						NTSTATUS *perr);
struct rpc_pipe_client *cli_rpc_pipe_open_schannel(struct cli_state *cli,
                                                int pipe_idx,
						enum pipe_auth_level auth_level,
                                                const char *domain,
						NTSTATUS *perr);
struct rpc_pipe_client *cli_rpc_pipe_open_krb5(struct cli_state *cli,
						int pipe_idx,
						enum pipe_auth_level auth_level,
						const char *service_princ,
						const char *username,
						const char *password,
						NTSTATUS *perr);

/* The following definitions come from rpc_client/init_lsa.c  */

void init_lsa_String(struct lsa_String *name, const char *s);
void init_lsa_StringLarge(struct lsa_StringLarge *name, const char *s);
void init_lsa_AsciiString(struct lsa_AsciiString *name, const char *s);
void init_lsa_AsciiStringLarge(struct lsa_AsciiStringLarge *name, const char *s);
void init_lsa_sec_qos(struct lsa_QosInfo *r,
		      uint32_t len,
		      uint16_t impersonation_level,
		      uint8_t context_mode,
		      uint8_t effective_only);
void init_lsa_obj_attr(struct lsa_ObjectAttribute *r,
		       uint32_t len,
		       uint8_t *root_dir,
		       const char *object_name,
		       uint32_t attributes,
		       struct security_descriptor *sec_desc,
		       struct lsa_QosInfo *sec_qos);
void init_lsa_translated_sid(struct lsa_TranslatedSid *r,
			     enum lsa_SidType sid_type,
			     uint32_t rid,
			     uint32_t sid_index);
void init_lsa_translated_name2(struct lsa_TranslatedName2 *r,
			       enum lsa_SidType sid_type,
			       const char *name,
			       uint32_t sid_index,
			       uint32_t unknown);

/* The following definitions come from rpc_client/init_netlogon.c  */

void init_netr_SamBaseInfo(struct netr_SamBaseInfo *r,
			   NTTIME last_logon,
			   NTTIME last_logoff,
			   NTTIME acct_expiry,
			   NTTIME last_password_change,
			   NTTIME allow_password_change,
			   NTTIME force_password_change,
			   const char *account_name,
			   const char *full_name,
			   const char *logon_script,
			   const char *profile_path,
			   const char *home_directory,
			   const char *home_drive,
			   uint16_t logon_count,
			   uint16_t bad_password_count,
			   uint32_t rid,
			   uint32_t primary_gid,
			   struct samr_RidWithAttributeArray groups,
			   uint32_t user_flags,
			   struct netr_UserSessionKey key,
			   const char *logon_server,
			   const char *domain,
			   struct dom_sid2 *domain_sid,
			   struct netr_LMSessionKey LMSessKey,
			   uint32_t acct_flags);
void init_netr_SamInfo3(struct netr_SamInfo3 *r,
			NTTIME last_logon,
			NTTIME last_logoff,
			NTTIME acct_expiry,
			NTTIME last_password_change,
			NTTIME allow_password_change,
			NTTIME force_password_change,
			const char *account_name,
			const char *full_name,
			const char *logon_script,
			const char *profile_path,
			const char *home_directory,
			const char *home_drive,
			uint16_t logon_count,
			uint16_t bad_password_count,
			uint32_t rid,
			uint32_t primary_gid,
			struct samr_RidWithAttributeArray groups,
			uint32_t user_flags,
			struct netr_UserSessionKey key,
			const char *logon_server,
			const char *domain,
			struct dom_sid2 *domain_sid,
			struct netr_LMSessionKey LMSessKey,
			uint32_t acct_flags,
			uint32_t sidcount,
			struct netr_SidAttr *sids);
NTSTATUS serverinfo_to_SamInfo3(struct auth_serversupplied_info *server_info,
				uint8_t pipe_session_key[16],
				struct netr_SamInfo3 *sam3);
void init_netr_IdentityInfo(struct netr_IdentityInfo *r,
			    const char *domain_name,
			    uint32_t parameter_control,
			    uint32_t logon_id_low,
			    uint32_t logon_id_high,
			    const char *account_name,
			    const char *workstation);
void init_netr_NetworkInfo(struct netr_NetworkInfo *r,
			   const char *domain_name,
			   uint32_t parameter_control,
			   uint32_t logon_id_low,
			   uint32_t logon_id_high,
			   const char *account_name,
			   const char *workstation,
			   uint8_t challenge[8],
			   struct netr_ChallengeResponse nt,
			   struct netr_ChallengeResponse lm);
void init_netr_PasswordInfo(struct netr_PasswordInfo *r,
			    const char *domain_name,
			    uint32_t parameter_control,
			    uint32_t logon_id_low,
			    uint32_t logon_id_high,
			    const char *account_name,
			    const char *workstation,
			    struct samr_Password lmpassword,
			    struct samr_Password ntpassword);

/* The following definitions come from rpc_client/init_srvsvc.c  */

void init_srvsvc_NetSrvInfo102(struct srvsvc_NetSrvInfo102 *r,
			       enum srvsvc_PlatformId platform_id,
			       const char *server_name,
			       uint32_t version_major,
			       uint32_t version_minor,
			       uint32_t server_type,
			       const char *comment,
			       uint32_t users,
			       uint32_t disc,
			       uint32_t hidden,
			       uint32_t announce,
			       uint32_t anndelta,
			       uint32_t licenses,
			       const char *userpath);
void init_srvsvc_NetSrvInfo101(struct srvsvc_NetSrvInfo101 *r,
			       enum srvsvc_PlatformId platform_id,
			       const char *server_name,
			       uint32_t version_major,
			       uint32_t version_minor,
			       uint32_t server_type,
			       const char *comment);
void init_srvsvc_NetSrvInfo100(struct srvsvc_NetSrvInfo100 *r,
			       enum srvsvc_PlatformId platform_id,
			       const char *server_name);
void init_srvsvc_NetShareInfo0(struct srvsvc_NetShareInfo0 *r,
			       const char *name);
void init_srvsvc_NetShareInfo1(struct srvsvc_NetShareInfo1 *r,
			       const char *name,
			       enum srvsvc_ShareType type,
			       const char *comment);
void init_srvsvc_NetShareInfo2(struct srvsvc_NetShareInfo2 *r,
			       const char *name,
			       enum srvsvc_ShareType type,
			       const char *comment,
			       uint32_t permissions,
			       uint32_t max_users,
			       uint32_t current_users,
			       const char *path,
			       const char *password);
void init_srvsvc_NetShareInfo501(struct srvsvc_NetShareInfo501 *r,
				 const char *name,
				 enum srvsvc_ShareType type,
				 const char *comment,
				 uint32_t csc_policy);
void init_srvsvc_NetShareInfo502(struct srvsvc_NetShareInfo502 *r,
				 const char *name,
				 enum srvsvc_ShareType type,
				 const char *comment,
				 uint32_t permissions,
				 uint32_t max_users,
				 uint32_t current_users,
				 const char *path,
				 const char *password,
				 struct sec_desc_buf *sd_buf);
void init_srvsvc_NetShareInfo1004(struct srvsvc_NetShareInfo1004 *r,
				  const char *comment);
void init_srvsvc_NetShareInfo1005(struct srvsvc_NetShareInfo1005 *r,
				  uint32_t dfs_flags);
void init_srvsvc_NetShareInfo1006(struct srvsvc_NetShareInfo1006 *r,
				  uint32_t max_users);
void init_srvsvc_NetShareInfo1007(struct srvsvc_NetShareInfo1007 *r,
				  uint32_t flags,
				  const char *alternate_directory_name);
void init_srvsvc_NetRemoteTODInfo(struct srvsvc_NetRemoteTODInfo *r,
				  uint32_t elapsed,
				  uint32_t msecs,
				  uint32_t hours,
				  uint32_t mins,
				  uint32_t secs,
				  uint32_t hunds,
				  int32_t ttimezone,
				  uint32_t tinterval,
				  uint32_t day,
				  uint32_t month,
				  uint32_t year,
				  uint32_t weekday);
void init_srvsvc_NetSessInfo0(struct srvsvc_NetSessInfo0 *r,
			      const char *client);
void init_srvsvc_NetSessInfo1(struct srvsvc_NetSessInfo1 *r,
			      const char *client,
			      const char *user,
			      uint32_t num_open,
			      uint32_t _time,
			      uint32_t idle_time,
			      uint32_t user_flags);
void init_srvsvc_NetSessInfo2(struct srvsvc_NetSessInfo2 *r,
			      const char *client,
			      const char *user,
			      uint32_t num_open,
			      uint32_t _time,
			      uint32_t idle_time,
			      uint32_t user_flags,
			      const char *client_type);
void init_srvsvc_NetSessInfo10(struct srvsvc_NetSessInfo10 *r,
			       const char *client,
			       const char *user,
			       uint32_t _time,
			       uint32_t idle_time);
void init_srvsvc_NetSessInfo502(struct srvsvc_NetSessInfo502 *r,
			       const char *client,
			       const char *user,
			       uint32_t num_open,
			       uint32_t _time,
			       uint32_t idle_time,
			       uint32_t user_flags,
			       const char *client_type,
			       const char *transport);
void init_srvsvc_NetFileInfo2(struct srvsvc_NetFileInfo2 *r,
			      uint32_t fid);
void init_srvsvc_NetFileInfo3(struct srvsvc_NetFileInfo3 *r,
			      uint32_t fid,
			      uint32_t permissions,
			      uint32_t num_locks,
			      const char *path,
			      const char *user);
void init_srvsvc_NetConnInfo0(struct srvsvc_NetConnInfo0 *r,
			      uint32_t conn_id);
void init_srvsvc_NetConnInfo1(struct srvsvc_NetConnInfo1 *r,
			      uint32_t conn_id,
			      uint32_t conn_type,
			      uint32_t num_open,
			      uint32_t num_users,
			      uint32_t conn_time,
			      const char *user,
			      const char *share);

/* The following definitions come from rpc_parse/parse_rpc.c  */

const char *cli_get_pipe_name(int pipe_idx);
int cli_get_pipe_idx(const RPC_IFACE *syntax);
void init_rpc_hdr(RPC_HDR *hdr, enum RPC_PKT_TYPE pkt_type, uint8 flags,
				uint32 call_id, int data_len, int auth_len);
bool smb_io_rpc_hdr(const char *desc,  RPC_HDR *rpc, prs_struct *ps, int depth);
void init_rpc_context(RPC_CONTEXT *rpc_ctx, uint16 context_id,
		      const RPC_IFACE *abstract, const RPC_IFACE *transfer);
void init_rpc_hdr_rb(RPC_HDR_RB *rpc, 
				uint16 max_tsize, uint16 max_rsize, uint32 assoc_gid,
				RPC_CONTEXT *context);
bool smb_io_rpc_context(const char *desc, RPC_CONTEXT *rpc_ctx, prs_struct *ps, int depth);
bool smb_io_rpc_hdr_rb(const char *desc, RPC_HDR_RB *rpc, prs_struct *ps, int depth);
void init_rpc_hdr_ba(RPC_HDR_BA *rpc, 
				uint16 max_tsize, uint16 max_rsize, uint32 assoc_gid,
				const char *pipe_addr,
				uint8 num_results, uint16 result, uint16 reason,
				RPC_IFACE *transfer);
bool smb_io_rpc_hdr_ba(const char *desc, RPC_HDR_BA *rpc, prs_struct *ps, int depth);
void init_rpc_hdr_req(RPC_HDR_REQ *hdr, uint32 alloc_hint, uint16 opnum);
bool smb_io_rpc_hdr_req(const char *desc, RPC_HDR_REQ *rpc, prs_struct *ps, int depth);
bool smb_io_rpc_hdr_resp(const char *desc, RPC_HDR_RESP *rpc, prs_struct *ps, int depth);
bool smb_io_rpc_hdr_fault(const char *desc, RPC_HDR_FAULT *rpc, prs_struct *ps, int depth);
void init_rpc_hdr_auth(RPC_HDR_AUTH *rai,
				uint8 auth_type, uint8 auth_level,
				uint8 auth_pad_len,
				uint32 auth_context_id);
bool smb_io_rpc_hdr_auth(const char *desc, RPC_HDR_AUTH *rai, prs_struct *ps, int depth);
bool rpc_auth_verifier_chk(RPC_AUTH_VERIFIER *rav,
				const char *signature, uint32 msg_type);
void init_rpc_auth_verifier(RPC_AUTH_VERIFIER *rav,
				const char *signature, uint32 msg_type);
bool smb_io_rpc_auth_verifier(const char *desc, RPC_AUTH_VERIFIER *rav, prs_struct *ps, int depth);
bool smb_io_rpc_schannel_verifier(const char *desc, RPC_AUTH_VERIFIER *rav, prs_struct *ps, int depth);
void init_rpc_auth_schannel_neg(RPC_AUTH_SCHANNEL_NEG *neg,
			      const char *domain, const char *myname);
bool smb_io_rpc_auth_schannel_neg(const char *desc, RPC_AUTH_SCHANNEL_NEG *neg,
				prs_struct *ps, int depth);
bool smb_io_rpc_auth_schannel_chk(const char *desc, int auth_len, 
                                RPC_AUTH_SCHANNEL_CHK * chk,
				prs_struct *ps, int depth);

#endif /*  _CLIENT_PROTO_H_  */
