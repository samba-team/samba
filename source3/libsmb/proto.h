/*
   Unix SMB/CIFS implementation.

   Copyright (C) Andrew Bartlett 2001-2003
   Copyright (C) Andrew Tridgell 1994-1998,2000-2001
   Copyright (C) Gerald (Jerry) Carter 2004
   Copyright (C) Jelmer Vernooij 2003
   Copyright (C) Jeremy Allison 2001-2009,2011
   Copyright (C) Stefan Metzmacher 2003,2009
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

#ifndef _LIBSMB_PROTO_H_
#define _LIBSMB_PROTO_H_

#include "auth_info.h"

struct smb_trans_enc_state;
struct cli_credentials;
struct cli_state;
struct file_info;
struct print_job_info;

/* The following definitions come from libsmb/cliconnect.c  */

struct cli_credentials *cli_session_creds_init(TALLOC_CTX *mem_ctx,
					       const char *username,
					       const char *domain,
					       const char *realm,
					       const char *password,
					       bool use_kerberos,
					       bool fallback_after_kerberos,
					       bool use_ccache,
					       bool password_is_nt_hash);
NTSTATUS cli_session_creds_prepare_krb5(struct cli_state *cli,
					struct cli_credentials *creds);
struct tevent_req *cli_session_setup_creds_send(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct cli_state *cli,
					struct cli_credentials *creds);
NTSTATUS cli_session_setup_creds_recv(struct tevent_req *req);
NTSTATUS cli_session_setup_creds(struct cli_state *cli,
				 struct cli_credentials *creds);
NTSTATUS cli_session_setup_anon(struct cli_state *cli);
struct tevent_req *cli_session_setup_guest_create(TALLOC_CTX *mem_ctx,
						  struct tevent_context *ev,
						  struct cli_state *cli,
						  struct tevent_req **psmbreq);
struct tevent_req *cli_session_setup_guest_send(TALLOC_CTX *mem_ctx,
						struct tevent_context *ev,
						struct cli_state *cli);
NTSTATUS cli_session_setup_guest_recv(struct tevent_req *req);
NTSTATUS cli_ulogoff(struct cli_state *cli);
struct tevent_req *cli_tcon_andx_create(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct cli_state *cli,
					const char *share, const char *dev,
					const char *pass, int passlen,
					struct tevent_req **psmbreq);
struct tevent_req *cli_tcon_andx_send(TALLOC_CTX *mem_ctx,
				      struct tevent_context *ev,
				      struct cli_state *cli,
				      const char *share, const char *dev,
				      const char *pass, int passlen);
NTSTATUS cli_tcon_andx_recv(struct tevent_req *req);
NTSTATUS cli_tcon_andx(struct cli_state *cli, const char *share,
		       const char *dev, const char *pass, int passlen);
NTSTATUS cli_tree_connect_creds(struct cli_state *cli,
				const char *share, const char *dev,
				struct cli_credentials *creds);
NTSTATUS cli_tree_connect(struct cli_state *cli, const char *share,
			  const char *dev, const char *pass);
NTSTATUS cli_tdis(struct cli_state *cli);
NTSTATUS cli_connect_nb(const char *host, const struct sockaddr_storage *dest_ss,
			uint16_t port, int name_type, const char *myname,
			int signing_state, int flags, struct cli_state **pcli);
NTSTATUS cli_start_connection(struct cli_state **output_cli,
			      const char *my_name,
			      const char *dest_host,
			      const struct sockaddr_storage *dest_ss, int port,
			      int signing_state, int flags);
NTSTATUS cli_smb1_setup_encryption(struct cli_state *cli,
				   struct cli_credentials *creds);
struct tevent_req *cli_full_connection_creds_send(
	TALLOC_CTX *mem_ctx, struct tevent_context *ev,
	const char *my_name, const char *dest_host,
	const struct sockaddr_storage *dest_ss, int port,
	const char *service, const char *service_type,
	struct cli_credentials *creds,
	int flags, int signing_state);
NTSTATUS cli_full_connection_creds_recv(struct tevent_req *req,
					struct cli_state **output_cli);
NTSTATUS cli_full_connection_creds(struct cli_state **output_cli,
				   const char *my_name,
				   const char *dest_host,
				   const struct sockaddr_storage *dest_ss, int port,
				   const char *service, const char *service_type,
				   struct cli_credentials *creds,
				   int flags,
				   int signing_state);
NTSTATUS cli_raw_tcon(struct cli_state *cli,
		      const char *service, const char *pass, const char *dev,
		      uint16_t *max_xmit, uint16_t *tid);
struct cli_state *get_ipc_connect(char *server,
				struct sockaddr_storage *server_ss,
				const struct user_auth_info *user_info);
struct cli_state *get_ipc_connect_master_ip(TALLOC_CTX *ctx,
				struct sockaddr_storage *mb_ip,
				const struct user_auth_info *user_info,
				char **pp_workgroup_out);

/* The following definitions come from libsmb/clidfs.c  */

NTSTATUS cli_cm_force_encryption_creds(struct cli_state *c,
				       struct cli_credentials *creds,
				       const char *sharename);
NTSTATUS cli_cm_open(TALLOC_CTX *ctx,
				struct cli_state *referring_cli,
				const char *server,
				const char *share,
				const struct user_auth_info *auth_info,
				bool force_encrypt,
				int max_protocol,
				const struct sockaddr_storage *dest_ss,
				int port,
				int name_type,
				struct cli_state **pcli);
void cli_cm_display(struct cli_state *c);
struct client_dfs_referral;
NTSTATUS cli_dfs_get_referral_ex(TALLOC_CTX *ctx,
			struct cli_state *cli,
			const char *path,
			uint16_t max_referral_level,
			struct client_dfs_referral **refs,
			size_t *num_refs,
			size_t *consumed);
NTSTATUS cli_dfs_get_referral(TALLOC_CTX *ctx,
			struct cli_state *cli,
			const char *path,
			struct client_dfs_referral **refs,
			size_t *num_refs,
			size_t *consumed);
NTSTATUS cli_resolve_path(TALLOC_CTX *ctx,
			  const char *mountpt,
			  const struct user_auth_info *dfs_auth_info,
			  struct cli_state *rootcli,
			  const char *path,
			  struct cli_state **targetcli,
			  char **pp_targetpath);

bool cli_check_msdfs_proxy(TALLOC_CTX *ctx,
			struct cli_state *cli,
			const char *sharename,
			char **pp_newserver,
			char **pp_newshare,
			bool force_encrypt,
			struct cli_credentials *creds);

/* The following definitions come from libsmb/clientgen.c  */

unsigned int cli_set_timeout(struct cli_state *cli, unsigned int timeout);
bool cli_set_backup_intent(struct cli_state *cli, bool flag);
extern struct GUID cli_state_client_guid;
struct cli_state *cli_state_create(TALLOC_CTX *mem_ctx,
				   int fd,
				   const char *remote_name,
				   int signing_state,
				   int flags);
void cli_nt_pipes_close(struct cli_state *cli);
void cli_shutdown(struct cli_state *cli);
uint16_t cli_state_get_vc_num(struct cli_state *cli);
uint32_t cli_setpid(struct cli_state *cli, uint32_t pid);
uint32_t cli_getpid(struct cli_state *cli);
bool cli_state_is_encryption_on(struct cli_state *cli);
bool cli_state_has_tcon(struct cli_state *cli);
uint32_t cli_state_get_tid(struct cli_state *cli);
uint32_t cli_state_set_tid(struct cli_state *cli, uint32_t tid);
struct smbXcli_tcon;
struct smbXcli_tcon *cli_state_save_tcon(struct cli_state *cli);
void cli_state_restore_tcon(struct cli_state *cli, struct smbXcli_tcon *tcon);
uint16_t cli_state_get_uid(struct cli_state *cli);
uint16_t cli_state_set_uid(struct cli_state *cli, uint16_t uid);
bool cli_set_case_sensitive(struct cli_state *cli, bool case_sensitive);
uint32_t cli_state_available_size(struct cli_state *cli, uint32_t ofs);
time_t cli_state_server_time(struct cli_state *cli);
struct tevent_req *cli_echo_send(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
				 struct cli_state *cli, uint16_t num_echos,
				 DATA_BLOB data);
NTSTATUS cli_echo_recv(struct tevent_req *req);
NTSTATUS cli_echo(struct cli_state *cli, uint16_t num_echos, DATA_BLOB data);
NTSTATUS cli_smb(TALLOC_CTX *mem_ctx, struct cli_state *cli,
		 uint8_t smb_command, uint8_t additional_flags,
		 uint8_t wct, uint16_t *vwv,
		 uint32_t num_bytes, const uint8_t *bytes,
		 struct tevent_req **result_parent,
		 uint8_t min_wct, uint8_t *pwct, uint16_t **pvwv,
		 uint32_t *pnum_bytes, uint8_t **pbytes);

/* The following definitions come from libsmb/clierror.c  */

NTSTATUS cli_nt_error(struct cli_state *cli);
void cli_dos_error(struct cli_state *cli, uint8_t *eclass, uint32_t *ecode);
int cli_errno(struct cli_state *cli);
bool cli_is_error(struct cli_state *cli);
bool cli_is_nt_error(struct cli_state *cli);
bool cli_is_dos_error(struct cli_state *cli);
bool cli_state_is_connected(struct cli_state *cli);

/* The following definitions come from libsmb/clifile.c  */

struct tevent_req *cli_setpathinfo_send(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct cli_state *cli,
					uint16_t level,
					const char *path,
					uint8_t *data,
					size_t data_len);
NTSTATUS cli_setpathinfo_recv(struct tevent_req *req);
NTSTATUS cli_setpathinfo(struct cli_state *cli,
			 uint16_t level,
			 const char *path,
			 uint8_t *data,
			 size_t data_len);
struct tevent_req *cli_setfileinfo_send(
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	struct cli_state *cli,
	uint16_t fnum,
	uint16_t level,
	uint8_t *data,
	size_t data_len);
NTSTATUS cli_setfileinfo_recv(struct tevent_req *req);

struct tevent_req *cli_posix_symlink_send(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct cli_state *cli,
					const char *oldname,
					const char *newname);
NTSTATUS cli_posix_symlink_recv(struct tevent_req *req);
NTSTATUS cli_posix_symlink(struct cli_state *cli,
			const char *oldname,
			const char *newname);
struct tevent_req *cli_posix_readlink_send(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct cli_state *cli,
					const char *fname);
NTSTATUS cli_posix_readlink_recv(
	struct tevent_req *req, TALLOC_CTX *mem_ctx, char **target);
NTSTATUS cli_posix_readlink(
	struct cli_state *cli,
	const char *fname,
	TALLOC_CTX *mem_ctx,
	char **target);
struct tevent_req *cli_posix_hardlink_send(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct cli_state *cli,
					const char *oldname,
					const char *newname);
NTSTATUS cli_posix_hardlink_recv(struct tevent_req *req);
NTSTATUS cli_posix_hardlink(struct cli_state *cli,
			const char *oldname,
			const char *newname);
uint32_t unix_perms_to_wire(mode_t perms);
mode_t wire_perms_to_unix(uint32_t perms);
struct tevent_req *cli_posix_getacl_send(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct cli_state *cli,
					const char *fname);
NTSTATUS cli_posix_getacl_recv(struct tevent_req *req,
				TALLOC_CTX *mem_ctx,
				size_t *prb_size,
				char **retbuf);
NTSTATUS cli_posix_getacl(struct cli_state *cli,
			const char *fname,
			TALLOC_CTX *mem_ctx,
			size_t *prb_size,
			char **retbuf);
struct tevent_req *cli_posix_setacl_send(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct cli_state *cli,
					const char *fname,
					const void *acl_buf,
					size_t acl_buf_size);
NTSTATUS cli_posix_setacl_recv(struct tevent_req *req);
NTSTATUS cli_posix_setacl(struct cli_state *cli,
			const char *fname,
			const void *acl_buf,
			size_t acl_buf_size);
struct tevent_req *cli_posix_stat_send(TALLOC_CTX *mem_ctx,
				       struct tevent_context *ev,
				       struct cli_state *cli,
				       const char *fname,
				       SMB_STRUCT_STAT *sbuf);
NTSTATUS cli_posix_stat_recv(struct tevent_req *req);
NTSTATUS cli_posix_stat(struct cli_state *cli,
			const char *fname,
			SMB_STRUCT_STAT *sbuf);
struct tevent_req *cli_posix_chmod_send(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct cli_state *cli,
					const char *fname,
					mode_t mode);
NTSTATUS cli_posix_chmod_recv(struct tevent_req *req);
NTSTATUS cli_posix_chmod(struct cli_state *cli, const char *fname, mode_t mode);
struct tevent_req *cli_posix_chown_send(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct cli_state *cli,
					const char *fname,
					uid_t uid,
					gid_t gid);
NTSTATUS cli_posix_chown_recv(struct tevent_req *req);
NTSTATUS cli_posix_chown(struct cli_state *cli,
			const char *fname,
			uid_t uid,
			gid_t gid);
struct tevent_req *cli_rename_send(TALLOC_CTX *mem_ctx,
				   struct tevent_context *ev,
				   struct cli_state *cli,
				   const char *fname_src,
				   const char *fname_dst,
				   bool replace);
NTSTATUS cli_rename_recv(struct tevent_req *req);
NTSTATUS cli_rename(struct cli_state *cli,
		    const char *fname_src,
		    const char *fname_dst,
		    bool replace);
struct tevent_req *cli_ntrename_send(TALLOC_CTX *mem_ctx,
                                struct tevent_context *ev,
                                struct cli_state *cli,
                                const char *fname_src,
                                const char *fname_dst);
NTSTATUS cli_ntrename_recv(struct tevent_req *req);
NTSTATUS cli_ntrename(struct cli_state *cli, const char *fname_src, const char *fname_dst);

struct tevent_req *cli_hardlink_send(
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	struct cli_state *cli,
	const char *fname_src,
	const char *fname_dst);
NTSTATUS cli_hardlink_recv(struct tevent_req *req);
NTSTATUS cli_hardlink(
	struct cli_state *cli,
	const char *fname_src,
	const char *fname_dst);

struct tevent_req *cli_unlink_send(TALLOC_CTX *mem_ctx,
                                struct tevent_context *ev,
                                struct cli_state *cli,
                                const char *fname,
                                uint32_t mayhave_attrs);
NTSTATUS cli_unlink_recv(struct tevent_req *req);
NTSTATUS cli_unlink(struct cli_state *cli, const char *fname, uint32_t mayhave_attrs);

struct tevent_req *cli_mkdir_send(TALLOC_CTX *mem_ctx,
				  struct tevent_context *ev,
				  struct cli_state *cli,
				  const char *dname);
NTSTATUS cli_mkdir_recv(struct tevent_req *req);
NTSTATUS cli_mkdir(struct cli_state *cli, const char *dname);
struct tevent_req *cli_rmdir_send(TALLOC_CTX *mem_ctx,
				  struct tevent_context *ev,
				  struct cli_state *cli,
				  const char *dname);
NTSTATUS cli_rmdir_recv(struct tevent_req *req);
NTSTATUS cli_rmdir(struct cli_state *cli, const char *dname);
struct tevent_req *cli_nt_delete_on_close_send(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct cli_state *cli,
					uint16_t fnum,
					bool flag);
NTSTATUS cli_nt_delete_on_close_recv(struct tevent_req *req);
NTSTATUS cli_nt_delete_on_close(struct cli_state *cli, uint16_t fnum, bool flag);
struct tevent_req *cli_ntcreate_send(TALLOC_CTX *mem_ctx,
				     struct tevent_context *ev,
				     struct cli_state *cli,
				     const char *fname,
				     uint32_t CreatFlags,
				     uint32_t DesiredAccess,
				     uint32_t FileAttributes,
				     uint32_t ShareAccess,
				     uint32_t CreateDisposition,
				     uint32_t CreateOptions,
				     uint32_t ImpersonationLevel,
				     uint8_t SecurityFlags);
NTSTATUS cli_ntcreate_recv(struct tevent_req *req,
			uint16_t *pfnum,
			struct smb_create_returns *cr);
NTSTATUS cli_ntcreate(struct cli_state *cli,
		      const char *fname,
		      uint32_t CreatFlags,
		      uint32_t DesiredAccess,
		      uint32_t FileAttributes,
		      uint32_t ShareAccess,
		      uint32_t CreateDisposition,
		      uint32_t CreateOptions,
		      uint8_t SecurityFlags,
		      uint16_t *pfid,
		      struct smb_create_returns *cr);
struct tevent_req *cli_openx_create(TALLOC_CTX *mem_ctx,
				   struct tevent_context *ev,
				   struct cli_state *cli, const char *fname,
				   int flags, int share_mode,
				   struct tevent_req **psmbreq);
struct tevent_req *cli_openx_send(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
				 struct cli_state *cli, const char *fname,
				 int flags, int share_mode);
NTSTATUS cli_openx_recv(struct tevent_req *req, uint16_t *fnum);
NTSTATUS cli_openx(struct cli_state *cli, const char *fname, int flags, int share_mode, uint16_t *pfnum);
NTSTATUS cli_open(struct cli_state *cli, const char *fname, int flags, int share_mode, uint16_t *pfnum);
struct tevent_req *cli_smb1_close_create(TALLOC_CTX *mem_ctx,
				    struct tevent_context *ev,
				    struct cli_state *cli, uint16_t fnum,
				    struct tevent_req **psubreq);
struct tevent_req *cli_close_send(TALLOC_CTX *mem_ctx,
				  struct tevent_context *ev,
				  struct cli_state *cli, uint16_t fnum);
NTSTATUS cli_close_recv(struct tevent_req *req);
NTSTATUS cli_close(struct cli_state *cli, uint16_t fnum);
struct tevent_req *cli_ftruncate_send(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct cli_state *cli,
					uint16_t fnum,
					uint64_t size);
NTSTATUS cli_ftruncate_recv(struct tevent_req *req);
NTSTATUS cli_ftruncate(struct cli_state *cli, uint16_t fnum, uint64_t size);
NTSTATUS cli_locktype(struct cli_state *cli, uint16_t fnum,
		      uint32_t offset, uint32_t len,
		      int timeout, unsigned char locktype);
struct smb1_lock_element {
	uint16_t pid;
	uint64_t offset;
	uint64_t length;
};

struct tevent_req *cli_lockingx_create(
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	struct cli_state *cli,
	uint16_t fnum,
	uint8_t typeoflock,
	uint8_t newoplocklevel,
	int32_t timeout,
	uint16_t num_unlocks,
	const struct smb1_lock_element *unlocks,
	uint16_t num_locks,
	const struct smb1_lock_element *locks,
	struct tevent_req **psmbreq);
struct tevent_req *cli_lockingx_send(
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	struct cli_state *cli,
	uint16_t fnum,
	uint8_t typeoflock,
	uint8_t newoplocklevel,
	int32_t timeout,
	uint16_t num_unlocks,
	const struct smb1_lock_element *unlocks,
	uint16_t num_locks,
	const struct smb1_lock_element *locks);
NTSTATUS cli_lockingx_recv(struct tevent_req *req);
NTSTATUS cli_lockingx(
	struct cli_state *cli,
	uint16_t fnum,
	uint8_t typeoflock,
	uint8_t newoplocklevel,
	int32_t timeout,
	uint16_t num_unlocks,
	const struct smb1_lock_element *unlocks,
	uint16_t num_locks,
	const struct smb1_lock_element *locks);

NTSTATUS cli_lock32(struct cli_state *cli, uint16_t fnum, uint32_t offset,
		    uint32_t len, int timeout, enum brl_type lock_type);
struct tevent_req *cli_unlock_send(TALLOC_CTX *mem_ctx,
                                struct tevent_context *ev,
                                struct cli_state *cli,
                                uint16_t fnum,
                                uint64_t offset,
                                uint64_t len);
NTSTATUS cli_unlock_recv(struct tevent_req *req);
NTSTATUS cli_unlock(struct cli_state *cli, uint16_t fnum, uint32_t offset, uint32_t len);
struct tevent_req *cli_posix_lock_send(TALLOC_CTX *mem_ctx,
                                        struct tevent_context *ev,
                                        struct cli_state *cli,
                                        uint16_t fnum,
                                        uint64_t offset,
                                        uint64_t len,
                                        bool wait_lock,
                                        enum brl_type lock_type);
NTSTATUS cli_posix_lock_recv(struct tevent_req *req);
NTSTATUS cli_posix_lock(struct cli_state *cli, uint16_t fnum,
			uint64_t offset, uint64_t len,
			bool wait_lock, enum brl_type lock_type);
struct tevent_req *cli_posix_unlock_send(TALLOC_CTX *mem_ctx,
                                        struct tevent_context *ev,
                                        struct cli_state *cli,
                                        uint16_t fnum,
                                        uint64_t offset,
                                        uint64_t len);
NTSTATUS cli_posix_unlock_recv(struct tevent_req *req);
NTSTATUS cli_posix_unlock(struct cli_state *cli, uint16_t fnum, uint64_t offset, uint64_t len);
struct tevent_req *cli_getattrE_send(TALLOC_CTX *mem_ctx,
				struct tevent_context *ev,
				struct cli_state *cli,
                                uint16_t fnum);
NTSTATUS cli_getattrE_recv(struct tevent_req *req,
                        uint32_t *pattr,
                        off_t *size,
                        time_t *change_time,
                        time_t *access_time,
                        time_t *write_time);
struct tevent_req *cli_setattrE_send(TALLOC_CTX *mem_ctx,
				struct tevent_context *ev,
				struct cli_state *cli,
				uint16_t fnum,
				time_t change_time,
				time_t access_time,
				time_t write_time);
NTSTATUS cli_setattrE_recv(struct tevent_req *req);
NTSTATUS cli_setattrE(struct cli_state *cli,
			uint16_t fnum,
			time_t change_time,
			time_t access_time,
			time_t write_time);
struct tevent_req *cli_getatr_send(TALLOC_CTX *mem_ctx,
				struct tevent_context *ev,
				struct cli_state *cli,
				const char *fname);
NTSTATUS cli_getatr_recv(struct tevent_req *req,
				uint32_t *pattr,
				off_t *size,
				time_t *write_time);
NTSTATUS cli_getatr(struct cli_state *cli,
			const char *fname,
			uint32_t *pattr,
			off_t *size,
			time_t *write_time);
struct tevent_req *cli_setatr_send(TALLOC_CTX *mem_ctx,
				struct tevent_context *ev,
				struct cli_state *cli,
				const char *fname,
				uint32_t attr,
				time_t mtime);
NTSTATUS cli_setatr_recv(struct tevent_req *req);
NTSTATUS cli_setatr(struct cli_state *cli,
                const char *fname,
                uint32_t attr,
                time_t mtime);
struct tevent_req *cli_chkpath_send(TALLOC_CTX *mem_ctx,
				  struct tevent_context *ev,
				  struct cli_state *cli,
				  const char *fname);
NTSTATUS cli_chkpath_recv(struct tevent_req *req);
NTSTATUS cli_chkpath(struct cli_state *cli, const char *path);
struct tevent_req *cli_dskattr_send(TALLOC_CTX *mem_ctx,
				  struct tevent_context *ev,
				  struct cli_state *cli);
NTSTATUS cli_dskattr_recv(struct tevent_req *req, int *bsize, int *total,
			  int *avail);
NTSTATUS cli_dskattr(struct cli_state *cli, int *bsize, int *total, int *avail);
NTSTATUS cli_disk_size(struct cli_state *cli, const char *path, uint64_t *bsize,
		       uint64_t *total, uint64_t *avail);
struct tevent_req *cli_ctemp_send(TALLOC_CTX *mem_ctx,
				struct tevent_context *ev,
				struct cli_state *cli,
				const char *path);
NTSTATUS cli_ctemp_recv(struct tevent_req *req,
			TALLOC_CTX *ctx,
			uint16_t *pfnum,
			char **outfile);
NTSTATUS cli_ctemp(struct cli_state *cli,
			TALLOC_CTX *ctx,
			const char *path,
			uint16_t *pfnum,
			char **out_path);
NTSTATUS cli_raw_ioctl(struct cli_state *cli, uint16_t fnum, uint32_t code, DATA_BLOB *blob);
NTSTATUS cli_set_ea_path(struct cli_state *cli, const char *path,
			 const char *ea_name, const char *ea_val,
			 size_t ea_len);
NTSTATUS cli_set_ea_fnum(struct cli_state *cli, uint16_t fnum,
			 const char *ea_name, const char *ea_val,
			 size_t ea_len);
struct tevent_req *cli_get_ea_list_path_send(TALLOC_CTX *mem_ctx,
					     struct tevent_context *ev,
					     struct cli_state *cli,
					     const char *fname);
NTSTATUS cli_get_ea_list_path_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
				   size_t *pnum_eas, struct ea_struct **peas);
NTSTATUS cli_get_ea_list_path(struct cli_state *cli, const char *path,
		TALLOC_CTX *ctx,
		size_t *pnum_eas,
		struct ea_struct **pea_list);
struct tevent_req *cli_posix_open_send(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct cli_state *cli,
					const char *fname,
					int flags,
					mode_t mode);
NTSTATUS cli_posix_open_recv(struct tevent_req *req, uint16_t *pfnum);
NTSTATUS cli_posix_open(struct cli_state *cli, const char *fname,
			int flags, mode_t mode, uint16_t *fnum);
struct tevent_req *cli_posix_mkdir_send(TALLOC_CTX *mem_ctx,
                                        struct tevent_context *ev,
                                        struct cli_state *cli,
                                        const char *fname,
                                        mode_t mode);
NTSTATUS cli_posix_mkdir_recv(struct tevent_req *req);
NTSTATUS cli_posix_mkdir(struct cli_state *cli, const char *fname, mode_t mode);

struct tevent_req *cli_posix_unlink_send(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct cli_state *cli,
					const char *fname);
NTSTATUS cli_posix_unlink_recv(struct tevent_req *req);
NTSTATUS cli_posix_unlink(struct cli_state *cli, const char *fname);

struct tevent_req *cli_posix_rmdir_send(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct cli_state *cli,
					const char *fname);
NTSTATUS cli_posix_rmdir_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx);
NTSTATUS cli_posix_rmdir(struct cli_state *cli, const char *fname);
struct tevent_req *cli_notify_send(TALLOC_CTX *mem_ctx,
				   struct tevent_context *ev,
				   struct cli_state *cli, uint16_t fnum,
				   uint32_t buffer_size,
				   uint32_t completion_filter, bool recursive);
NTSTATUS cli_notify_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
			 uint32_t *pnum_changes,
			 struct notify_change **pchanges);
NTSTATUS cli_notify(struct cli_state *cli, uint16_t fnum, uint32_t buffer_size,
		    uint32_t completion_filter, bool recursive,
		    TALLOC_CTX *mem_ctx, uint32_t *pnum_changes,
		    struct notify_change **pchanges);

struct tevent_req *cli_nttrans_create_send(TALLOC_CTX *mem_ctx,
					   struct tevent_context *ev,
					   struct cli_state *cli,
					   const char *fname,
					   uint32_t CreatFlags,
					   uint32_t DesiredAccess,
					   uint32_t FileAttributes,
					   uint32_t ShareAccess,
					   uint32_t CreateDisposition,
					   uint32_t CreateOptions,
					   uint8_t SecurityFlags,
					   struct security_descriptor *secdesc,
					   struct ea_struct *eas,
					   int num_eas);
NTSTATUS cli_nttrans_create_recv(struct tevent_req *req,
			uint16_t *fnum,
			struct smb_create_returns *cr);
NTSTATUS cli_nttrans_create(struct cli_state *cli,
			    const char *fname,
			    uint32_t CreatFlags,
			    uint32_t DesiredAccess,
			    uint32_t FileAttributes,
			    uint32_t ShareAccess,
			    uint32_t CreateDisposition,
			    uint32_t CreateOptions,
			    uint8_t SecurityFlags,
			    struct security_descriptor *secdesc,
			    struct ea_struct *eas,
			    int num_eas,
			    uint16_t *pfid,
			    struct smb_create_returns *cr);

/* The following definitions come from libsmb/clifsinfo.c  */

struct tevent_req *cli_unix_extensions_version_send(TALLOC_CTX *mem_ctx,
						    struct tevent_context *ev,
						    struct cli_state *cli);
NTSTATUS cli_unix_extensions_version_recv(struct tevent_req *req,
					  uint16_t *pmajor, uint16_t *pminor,
					  uint32_t *pcaplow,
					  uint32_t *pcaphigh);
NTSTATUS cli_unix_extensions_version(struct cli_state *cli, uint16_t *pmajor,
				     uint16_t *pminor, uint32_t *pcaplow,
				     uint32_t *pcaphigh);
struct tevent_req *cli_set_unix_extensions_capabilities_send(
	TALLOC_CTX *mem_ctx, struct tevent_context *ev, struct cli_state *cli,
	uint16_t major, uint16_t minor, uint32_t caplow, uint32_t caphigh);
NTSTATUS cli_set_unix_extensions_capabilities_recv(struct tevent_req *req);
NTSTATUS cli_set_unix_extensions_capabilities(struct cli_state *cli,
					      uint16_t major, uint16_t minor,
					      uint32_t caplow, uint32_t caphigh);
struct tevent_req *cli_get_fs_attr_info_send(TALLOC_CTX *mem_ctx,
					     struct tevent_context *ev,
					     struct cli_state *cli);
NTSTATUS cli_get_fs_attr_info_recv(struct tevent_req *req, uint32_t *fs_attr);
NTSTATUS cli_get_fs_attr_info(struct cli_state *cli, uint32_t *fs_attr);
NTSTATUS cli_get_fs_volume_info(struct cli_state *cli,
				TALLOC_CTX *mem_ctx, char **volume_name,
				uint32_t *pserial_number, time_t *pdate);
NTSTATUS cli_get_fs_full_size_info(struct cli_state *cli,
				   uint64_t *total_allocation_units,
				   uint64_t *caller_allocation_units,
				   uint64_t *actual_allocation_units,
				   uint64_t *sectors_per_allocation_unit,
				   uint64_t *bytes_per_sector);
NTSTATUS cli_get_posix_fs_info(struct cli_state *cli,
			       uint32_t *optimal_transfer_size,
			       uint32_t *block_size,
			       uint64_t *total_blocks,
			       uint64_t *blocks_available,
			       uint64_t *user_blocks_available,
			       uint64_t *total_file_nodes,
			       uint64_t *free_file_nodes,
			       uint64_t *fs_identifier);
struct tevent_req *cli_posix_whoami_send(TALLOC_CTX *mem_ctx,
			struct tevent_context *ev,
			struct cli_state *cli);
NTSTATUS cli_posix_whoami_recv(struct tevent_req *req,
			TALLOC_CTX *mem_ctx,
			uint64_t *puid,
			uint64_t *pgid,
			uint32_t *pnum_gids,
			uint64_t **pgids,
			uint32_t *pnum_sids,
			struct dom_sid **psids,
			bool *pguest);
NTSTATUS cli_posix_whoami(struct cli_state *cli,
			TALLOC_CTX *mem_ctx,
			uint64_t *puid,
			uint64_t *pgid,
			uint32_t *num_gids,
			uint64_t **gids,
			uint32_t *num_sids,
			struct dom_sid **sids,
			bool *pguest);

/* The following definitions come from libsmb/clilist.c  */

NTSTATUS is_bad_finfo_name(const struct cli_state *cli,
			const struct file_info *finfo);

NTSTATUS cli_list_old(struct cli_state *cli,const char *Mask,uint32_t attribute,
		      NTSTATUS (*fn)(const char *, struct file_info *,
				 const char *, void *), void *state);
NTSTATUS cli_list_trans(struct cli_state *cli, const char *mask,
			uint32_t attribute, int info_level,
			NTSTATUS (*fn)(const char *mnt, struct file_info *finfo,
				   const char *mask, void *private_data),
			void *private_data);
struct tevent_req *cli_list_send(TALLOC_CTX *mem_ctx,
				 struct tevent_context *ev,
				 struct cli_state *cli,
				 const char *mask,
				 uint32_t attribute,
				 uint16_t info_level);
NTSTATUS cli_list_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
		       struct file_info **finfo, size_t *num_finfo);
NTSTATUS cli_list(struct cli_state *cli,const char *Mask,uint32_t attribute,
		  NTSTATUS (*fn)(const char *, struct file_info *, const char *,
			     void *), void *state);

/* The following definitions come from libsmb/climessage.c  */

struct tevent_req *cli_message_send(TALLOC_CTX *mem_ctx,
				    struct tevent_context *ev,
				    struct cli_state *cli,
				    const char *host, const char *username,
				    const char *message);
NTSTATUS cli_message_recv(struct tevent_req *req);
NTSTATUS cli_message(struct cli_state *cli, const char *host,
		     const char *username, const char *message);

/* The following definitions come from libsmb/clioplock.c  */

struct tevent_req *cli_smb_oplock_break_waiter_send(TALLOC_CTX *mem_ctx,
						    struct tevent_context *ev,
						    struct cli_state *cli);
NTSTATUS cli_smb_oplock_break_waiter_recv(struct tevent_req *req,
					  uint16_t *pfnum,
					  uint8_t *plevel);

struct tevent_req *cli_oplock_ack_send(TALLOC_CTX *mem_ctx,
				       struct tevent_context *ev,
				       struct cli_state *cli,
				       uint16_t fnum, uint8_t level);
NTSTATUS cli_oplock_ack_recv(struct tevent_req *req);

/* The following definitions come from libsmb/cliprint.c  */

int cli_print_queue(struct cli_state *cli,
		    void (*fn)(struct print_job_info *));
int cli_printjob_del(struct cli_state *cli, int job);

/* The following definitions come from libsmb/cliquota.c  */

NTSTATUS cli_get_quota_handle(struct cli_state *cli, uint16_t *quota_fnum);
void free_ntquota_list(SMB_NTQUOTA_LIST **qt_list);
bool parse_user_quota_record(const uint8_t *rdata,
			     unsigned int rdata_count,
			     unsigned int *offset,
			     SMB_NTQUOTA_STRUCT *pqt);
bool add_record_to_ntquota_list(TALLOC_CTX *mem_ctx,
				SMB_NTQUOTA_STRUCT *pqt,
				SMB_NTQUOTA_LIST **pqt_list);
NTSTATUS parse_user_quota_list(const uint8_t *curdata,
			       uint32_t curdata_size,
			       TALLOC_CTX *mem_ctx,
			       SMB_NTQUOTA_LIST **pqt_list);
NTSTATUS parse_fs_quota_buffer(const uint8_t *rdata,
			       unsigned int rdata_count,
			       SMB_NTQUOTA_STRUCT *pqt);
NTSTATUS build_user_quota_buffer(SMB_NTQUOTA_LIST *qt_list,
				 uint32_t maxlen,
				 TALLOC_CTX *mem_ctx,
				 DATA_BLOB *outbuf,
				 SMB_NTQUOTA_LIST **end_ptr);
NTSTATUS build_fs_quota_buffer(TALLOC_CTX *mem_ctx,
			       const SMB_NTQUOTA_STRUCT *pqt,
			       DATA_BLOB *blob,
			       uint32_t maxlen);
NTSTATUS cli_get_user_quota(struct cli_state *cli, int quota_fnum,
			    SMB_NTQUOTA_STRUCT *pqt);
NTSTATUS cli_set_user_quota(struct cli_state *cli,
			    int quota_fnum,
			    SMB_NTQUOTA_LIST *qtl);
NTSTATUS cli_list_user_quota(struct cli_state *cli, int quota_fnum,
			     SMB_NTQUOTA_LIST **pqt_list);
NTSTATUS cli_get_fs_quota_info(struct cli_state *cli, int quota_fnum,
			       SMB_NTQUOTA_STRUCT *pqt);
NTSTATUS cli_set_fs_quota_info(struct cli_state *cli, int quota_fnum,
			       SMB_NTQUOTA_STRUCT *pqt);

/* The following definitions come from libsmb/clireadwrite.c  */

struct tevent_req *cli_read_andx_create(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct cli_state *cli, uint16_t fnum,
					off_t offset, size_t size,
					struct tevent_req **psmbreq);
struct tevent_req *cli_read_andx_send(TALLOC_CTX *mem_ctx,
				      struct tevent_context *ev,
				      struct cli_state *cli, uint16_t fnum,
				      off_t offset, size_t size);
NTSTATUS cli_read_andx_recv(struct tevent_req *req, ssize_t *received,
			    uint8_t **rcvbuf);
struct tevent_req *cli_pull_send(TALLOC_CTX *mem_ctx,
				 struct tevent_context *ev,
				 struct cli_state *cli,
				 uint16_t fnum, off_t start_offset,
				 off_t size, size_t window_size,
				 NTSTATUS (*sink)(char *buf, size_t n,
						  void *priv),
				 void *priv);
NTSTATUS cli_pull_recv(struct tevent_req *req, off_t *received);
NTSTATUS cli_pull(struct cli_state *cli, uint16_t fnum,
		  off_t start_offset, off_t size, size_t window_size,
		  NTSTATUS (*sink)(char *buf, size_t n, void *priv),
		  void *priv, off_t *received);
NTSTATUS cli_read_sink(char *buf, size_t n, void *priv);
struct tevent_req *cli_read_send(
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	struct cli_state *cli,
	uint16_t fnum,
	char *buf,
	off_t offset,
	size_t size);
NTSTATUS cli_read_recv(struct tevent_req *req, size_t *received);
NTSTATUS cli_read(struct cli_state *cli, uint16_t fnum,
		  char *buf, off_t offset, size_t size,
		  size_t *nread);
NTSTATUS cli_smbwrite(struct cli_state *cli, uint16_t fnum, char *buf,
		      off_t offset, size_t size1, size_t *ptotal);
struct tevent_req *cli_write_andx_create(TALLOC_CTX *mem_ctx,
					 struct tevent_context *ev,
					 struct cli_state *cli, uint16_t fnum,
					 uint16_t mode, const uint8_t *buf,
					 off_t offset, size_t size,
					 struct tevent_req **reqs_before,
					 int num_reqs_before,
					 struct tevent_req **psmbreq);
struct tevent_req *cli_write_andx_send(TALLOC_CTX *mem_ctx,
				       struct tevent_context *ev,
				       struct cli_state *cli, uint16_t fnum,
				       uint16_t mode, const uint8_t *buf,
				       off_t offset, size_t size);
NTSTATUS cli_write_andx_recv(struct tevent_req *req, size_t *pwritten);

struct tevent_req *cli_write_send(TALLOC_CTX *mem_ctx,
				  struct tevent_context *ev,
				  struct cli_state *cli, uint16_t fnum,
				  uint16_t mode, const uint8_t *buf,
				  off_t offset, size_t size);
NTSTATUS cli_write_recv(struct tevent_req *req, size_t *pwritten);

struct tevent_req *cli_writeall_send(
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	struct cli_state *cli,
	uint16_t fnum,
	uint16_t mode,
	const uint8_t *buf,
	off_t offset,
	size_t size);
NTSTATUS cli_writeall_recv(struct tevent_req *req, size_t *pwritten);
NTSTATUS cli_writeall(struct cli_state *cli, uint16_t fnum, uint16_t mode,
		      const uint8_t *buf, off_t offset, size_t size,
		      size_t *pwritten);

struct tevent_req *cli_push_send(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
				 struct cli_state *cli,
				 uint16_t fnum, uint16_t mode,
				 off_t start_offset, size_t window_size,
				 size_t (*source)(uint8_t *buf, size_t n,
						  void *priv),
				 void *priv);
NTSTATUS cli_push_recv(struct tevent_req *req);
NTSTATUS cli_push(struct cli_state *cli, uint16_t fnum, uint16_t mode,
		  off_t start_offset, size_t window_size,
		  size_t (*source)(uint8_t *buf, size_t n, void *priv),
		  void *priv);

NTSTATUS cli_splice(struct cli_state *srccli, struct cli_state *dstcli,
		    uint16_t src_fnum, uint16_t dst_fnum,
		    off_t size,
		    off_t src_offset, off_t dst_offset,
		    off_t *written,
		    int (*splice_cb)(off_t n, void *priv), void *priv);

/* The following definitions come from libsmb/clisecdesc.c  */

NTSTATUS cli_query_security_descriptor(struct cli_state *cli,
				       uint16_t fnum,
				       uint32_t sec_info,
				       TALLOC_CTX *mem_ctx,
				       struct security_descriptor **sd);
NTSTATUS cli_query_secdesc(struct cli_state *cli, uint16_t fnum,
			  TALLOC_CTX *mem_ctx, struct security_descriptor **sd);
NTSTATUS cli_set_security_descriptor(struct cli_state *cli,
				     uint16_t fnum,
				     uint32_t sec_info,
				     const struct security_descriptor *sd);
NTSTATUS cli_set_secdesc(struct cli_state *cli, uint16_t fnum,
			 const struct security_descriptor *sd);

NTSTATUS cli_query_mxac(struct cli_state *cli,
			const char *filename,
			uint32_t *mxac);

/* The following definitions come from libsmb/clistr.c  */

bool clistr_is_previous_version_path(const char *path,
			const char **startp,
			const char **endp,
			time_t *ptime);

/* The following definitions come from libsmb/clitrans.c  */

struct tevent_req *cli_trans_send(
	TALLOC_CTX *mem_ctx, struct tevent_context *ev,
	struct cli_state *cli, uint16_t additional_flags2, uint8_t cmd,
	const char *pipe_name, uint16_t fid, uint16_t function, int flags,
	uint16_t *setup, uint8_t num_setup, uint8_t max_setup,
	uint8_t *param, uint32_t num_param, uint32_t max_param,
	uint8_t *data, uint32_t num_data, uint32_t max_data);
NTSTATUS cli_trans_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
			uint16_t *recv_flags2,
			uint16_t **setup, uint8_t min_setup,
			uint8_t *num_setup,
			uint8_t **param, uint32_t min_param,
			uint32_t *num_param,
			uint8_t **data, uint32_t min_data,
			uint32_t *num_data);
NTSTATUS cli_trans(TALLOC_CTX *mem_ctx, struct cli_state *cli,
		   uint8_t trans_cmd,
		   const char *pipe_name, uint16_t fid, uint16_t function,
		   int flags,
		   uint16_t *setup, uint8_t num_setup, uint8_t max_setup,
		   uint8_t *param, uint32_t num_param, uint32_t max_param,
		   uint8_t *data, uint32_t num_data, uint32_t max_data,
		   uint16_t *recv_flags2,
		   uint16_t **rsetup, uint8_t min_rsetup, uint8_t *num_rsetup,
		   uint8_t **rparam, uint32_t min_rparam, uint32_t *num_rparam,
		   uint8_t **rdata, uint32_t min_rdata, uint32_t *num_rdata);

/* The following definitions come from libsmb/reparse_symlink.c  */

bool symlink_reparse_buffer_marshall(
	const char *substitute, const char *printname, uint32_t flags,
	TALLOC_CTX *mem_ctx, uint8_t **pdst, size_t *pdstlen);
bool symlink_reparse_buffer_parse(
	const uint8_t *src, size_t srclen, TALLOC_CTX *mem_ctx,
	char **psubstitute_name, char **pprint_name, uint32_t *pflags);

/* The following definitions come from libsmb/clisymlink.c  */

struct tevent_req *cli_symlink_send(TALLOC_CTX *mem_ctx,
				    struct tevent_context *ev,
				    struct cli_state *cli,
				    const char *oldpath,
				    const char *newpath,
				    uint32_t flags);
NTSTATUS cli_symlink_recv(struct tevent_req *req);
NTSTATUS cli_symlink(struct cli_state *cli, const char *oldname,
		     const char *newname, uint32_t flags);

struct tevent_req *cli_readlink_send(TALLOC_CTX *mem_ctx,
				     struct tevent_context *ev,
				     struct cli_state *cli,
				     const char *fname);
NTSTATUS cli_readlink_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
			   char **psubstitute_name, char **pprint_name,
			   uint32_t *pflags);
NTSTATUS cli_readlink(struct cli_state *cli, const char *fname,
		       TALLOC_CTX *mem_ctx, char **psubstitute_name,
		      char **pprint_name, uint32_t *pflags);

NTSTATUS fill_quota_buffer(TALLOC_CTX *mem_ctx,
			   SMB_NTQUOTA_LIST *tmp_list,
			   bool return_single,
			   uint32_t max_data,
			   DATA_BLOB *blob,
			   SMB_NTQUOTA_LIST **end_ptr);
/* The following definitions come from libsmb/passchange.c  */

NTSTATUS remote_password_change(const char *remote_machine,
				const char *domain, const char *user_name,
				const char *old_passwd, const char *new_passwd,
				char **err_str);

#endif /* _LIBSMB_PROTO_H_ */
