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

#ifndef _PROTO_H_
#define _PROTO_H_

#include <sys/types.h>
#include <regex.h>

#include "lib/util/access.h"
#include "nsswitch/libwbclient/wbclient.h"

/* The following definitions come from lib/adt_tree.c  */

/* The following definitions come from lib/audit.c  */

const char *audit_category_str(uint32_t category);
const char *audit_param_str(uint32_t category);
const char *audit_description_str(uint32_t category);
bool get_audit_category_from_param(const char *param, uint32_t *audit_category);
const char *audit_policy_str(TALLOC_CTX *mem_ctx, uint32_t policy);

/* The following definitions come from lib/charcnv.c  */

void gfree_charcnv(void);
size_t push_ascii(void *dest, const char *src, size_t dest_len, int flags);
size_t push_ascii_fstring(void *dest, const char *src);
size_t push_ascii_nstring(void *dest, const char *src);
size_t pull_ascii(char *dest, const void *src, size_t dest_len, size_t src_len, int flags);
size_t pull_ascii_fstring(char *dest, const void *src);
size_t pull_ascii_nstring(char *dest, size_t dest_len, const void *src);
size_t push_string_check_fn(void *dest, const char *src,
			    size_t dest_len, int flags);
size_t push_string_base(const char *base, uint16_t flags2,
			void *dest, const char *src,
			size_t dest_len, int flags);
size_t pull_string_talloc(TALLOC_CTX *ctx,
			const void *base_ptr,
			uint16_t smb_flags2,
			char **ppdest,
			const void *src,
			size_t src_len,
			int flags);
size_t dos_PutUniCode(char *dst,const char *src, size_t len, bool null_terminate);
int rpcstr_push_talloc(TALLOC_CTX *ctx, smb_ucs2_t **dest, const char *src);

/* The following definitions come from lib/dmallocmsg.c  */

void register_dmalloc_msgs(struct messaging_context *msg_ctx);

/* The following definitions come from lib/dprintf.c  */

void display_set_stderr(void);

/* The following definitions come from lib/errmap_unix.c  */

NTSTATUS map_nt_error_from_unix(int unix_error);

/* The following definitions come from lib/file_id.c  */

struct file_id vfs_file_id_from_sbuf(connection_struct *conn, const SMB_STRUCT_STAT *sbuf);

NTSTATUS vfs_at_fspcwd(TALLOC_CTX *mem_ctx,
		       struct connection_struct *conn,
		       struct files_struct **_fsp);

#include "source3/lib/interface.h"

/* The following definitions come from lib/ldap_debug_handler.c  */

void init_ldap_debugging(void);

/* The following definitions come from lib/ldap_escape.c  */

char *escape_ldap_string(TALLOC_CTX *mem_ctx, const char *s);
char *escape_rdn_val_string_alloc(const char *s);

/* The following definitions come from lib/ms_fnmatch.c  */

int ms_fnmatch(const char *pattern, const char *string, bool translate_pattern,
	       bool is_case_sensitive);

/* The following definitions come from lib/recvfile.c  */

ssize_t sys_recvfile(int fromfd,
			int tofd,
			off_t offset,
			size_t count);
ssize_t sys_recvfile(int fromfd,
			int tofd,
			off_t offset,
			size_t count);
ssize_t drain_socket(int sockfd, size_t count);

/* The following definitions come from lib/sendfile.c  */

ssize_t sys_sendfile(int tofd, int fromfd, const DATA_BLOB *header, off_t offset, size_t count);

/* The following definitions come from lib/server_mutex.c  */

struct named_mutex *grab_named_mutex(TALLOC_CTX *mem_ctx, const char *name,
				     int timeout);

/* The following definitions come from lib/sharesec.c  */

NTSTATUS share_info_db_init(void);
struct security_descriptor *get_share_security( TALLOC_CTX *ctx, const char *servicename,
			      size_t *psize);
NTSTATUS set_share_security(const char *share_name,
			    struct security_descriptor *psd);
NTSTATUS delete_share_security(const char *servicename);
bool share_access_check(const struct security_token *token,
			const char *sharename,
			uint32_t desired_access,
			uint32_t *pgranted);
bool parse_usershare_acl(TALLOC_CTX *ctx, const char *acl_str, struct security_descriptor **ppsd);

/* The following definitions come from lib/smbrun.c  */

int smbrun_no_sanitize(const char *cmd, int *outfd, char * const *env);
int smbrun(const char *cmd, int *outfd, char * const *env);
int smbrunsecret(const char *cmd, const char *secret);

/* The following definitions come from lib/sysquotas.c  */

int sys_get_quota(const char *path, enum SMB_QUOTA_TYPE qtype, unid_t id, SMB_DISK_QUOTA *dp);
int sys_set_quota(const char *path, enum SMB_QUOTA_TYPE qtype, unid_t id, SMB_DISK_QUOTA *dp);

/* The following definitions come from lib/sysquotas_*.c  */

int sys_get_vfs_quota(const char *path, const char *bdev, enum SMB_QUOTA_TYPE qtype, unid_t id, SMB_DISK_QUOTA *dp);
int sys_set_vfs_quota(const char *path, const char *bdev, enum SMB_QUOTA_TYPE qtype, unid_t id, SMB_DISK_QUOTA *dp);

int sys_get_xfs_quota(const char *path, const char *bdev, enum SMB_QUOTA_TYPE qtype, unid_t id, SMB_DISK_QUOTA *dp);
int sys_set_xfs_quota(const char *path, const char *bdev, enum SMB_QUOTA_TYPE qtype, unid_t id, SMB_DISK_QUOTA *dp);

int sys_get_jfs2_quota(const char *path, const char *bdev, enum SMB_QUOTA_TYPE qtype, unid_t id, SMB_DISK_QUOTA *dp);
int sys_set_jfs2_quota(const char *path, const char *bdev, enum SMB_QUOTA_TYPE qtype, unid_t id, SMB_DISK_QUOTA *dp);

int sys_get_nfs_quota(const char *path, const char *bdev,
		      enum SMB_QUOTA_TYPE qtype,
		      unid_t id, SMB_DISK_QUOTA *dp);
int sys_set_nfs_quota(const char *path, const char *bdev,
		      enum SMB_QUOTA_TYPE qtype,
		      unid_t id, SMB_DISK_QUOTA *dp);

/* The following definitions come from lib/system.c  */

ssize_t sys_send(int s, const void *msg, size_t len, int flags);
ssize_t sys_recvfrom(int s, void *buf, size_t len, int flags, struct sockaddr *from, socklen_t *fromlen);
int sys_fcntl_ptr(int fd, int cmd, void *arg);
int sys_fcntl_long(int fd, int cmd, long arg);
int sys_fcntl_int(int fd, int cmd, int arg);
void update_stat_ex_mtime(struct stat_ex *dst, struct timespec write_ts);
void update_stat_ex_create_time(struct stat_ex *dst, struct timespec create_time);
void update_stat_ex_from_saved_stat(struct stat_ex *dst,
				    const struct stat_ex *src);
void copy_stat_ex_timestamps(struct stat_ex *st,
			     const struct smb_file_time *ft);
int sys_stat(const char *fname, SMB_STRUCT_STAT *sbuf,
	     bool fake_dir_create_times);
int sys_fstat(int fd, SMB_STRUCT_STAT *sbuf,
	      bool fake_dir_create_times);
int sys_lstat(const char *fname,SMB_STRUCT_STAT *sbuf,
	      bool fake_dir_create_times);
int sys_fstatat(int fd,
		const char *pathname,
		SMB_STRUCT_STAT *sbuf,
		int flags,
		bool fake_dir_create_times);
int sys_posix_fallocate(int fd, off_t offset, off_t len);
int sys_fallocate(int fd, uint32_t mode, off_t offset, off_t len);
DIR *sys_fdopendir(int fd);
int sys_mknod(const char *path, mode_t mode, SMB_DEV_T dev);
int sys_mknodat(int dirfd, const char *path, mode_t mode, SMB_DEV_T dev);
char *sys_getwd(void);
void set_effective_capability(enum smbd_capability capability);
void drop_effective_capability(enum smbd_capability capability);
long sys_random(void);
void sys_srandom(unsigned int seed);
int getgroups_max(void);
int setgroups_max(void);
int sys_getgroups(int setlen, gid_t *gidset);
int sys_setgroups(gid_t UNUSED(primary_gid), int setlen, gid_t *gidset);
uint32_t unix_dev_major(SMB_DEV_T dev);
uint32_t unix_dev_minor(SMB_DEV_T dev);
char *sys_realpath(const char *path);
#if 0
int sys_get_number_of_cores(void);
#endif

struct sys_proc_fd_path_buf {
	char buf[35]; /* "/proc/self/fd/" + strlen(2^64) + 0-terminator */
};
bool sys_have_proc_fds(void);
char *sys_proc_fd_path(int fd, struct sys_proc_fd_path_buf *buf);

struct stat;
void init_stat_ex_from_stat (struct stat_ex *dst,
			    const struct stat *src,
			    bool fake_dir_create_times);

/* The following definitions come from lib/system_smbd.c  */

bool getgroups_unix_user(TALLOC_CTX *mem_ctx, const char *user,
			 gid_t primary_gid,
			 gid_t **ret_groups, uint32_t *p_ngroups);

/* The following definitions come from lib/time.c  */

uint32_t convert_time_t_to_uint32_t(time_t t);
time_t convert_uint32_t_to_time_t(uint32_t u);
bool nt_time_is_zero(const NTTIME *nt);
time_t generalized_to_unix_time(const char *str);
int get_server_zone_offset(void);
int set_server_zone_offset(time_t t);
char *timeval_string(TALLOC_CTX *ctx, const struct timeval *tp, bool hires);
char *current_timestring(TALLOC_CTX *ctx, bool hires);
void srv_put_dos_date(char *buf,int offset,time_t unixdate);
void srv_put_dos_date2_ts(char *buf, int offset, struct timespec unix_ts);
void srv_put_dos_date3(char *buf,int offset,time_t unixdate);
void round_timespec(enum timestamp_set_resolution res, struct timespec *ts);
void put_long_date_timespec(enum timestamp_set_resolution res, char *p, struct timespec ts);
void put_long_date_full_timespec(enum timestamp_set_resolution res,
				 char *p,
				 const struct timespec *ts);
struct timespec pull_long_date_full_timespec(const char *p);
void put_long_date(char *p, time_t t);
void dos_filetime_timespec(struct timespec *tsp);
time_t make_unix_date(const void *date_ptr, int zone_offset);
time_t make_unix_date2(const void *date_ptr, int zone_offset);
time_t make_unix_date3(const void *date_ptr, int zone_offset);
time_t srv_make_unix_date(const void *date_ptr);
time_t srv_make_unix_date2(const void *date_ptr);
time_t srv_make_unix_date3(const void *date_ptr);
struct timespec interpret_long_date(NTTIME nt);
void TimeInit(void);
void get_process_uptime(struct timeval *ret_time);
void get_startup_time(struct timeval *ret_time);
time_t nt_time_to_unix_abs(const NTTIME *nt);
void unix_to_nt_time_abs(NTTIME *nt, time_t t);
const char *time_to_asc(const time_t t);
const char *display_time(NTTIME nttime);
bool nt_time_is_set(const NTTIME *nt);

/* The following definitions come from lib/username.c  */

void flush_pwnam_cache(void);
char *get_user_home_dir(TALLOC_CTX *mem_ctx, const char *user);
struct passwd *Get_Pwnam_alloc(TALLOC_CTX *mem_ctx, const char *user);

/* The following definitions come from lib/util_names.c  */
const char *get_global_sam_name(void);
const char *my_sam_name(void);
bool is_allowed_domain(const char *domain_name);

/* The following definitions come from lib/util.c  */

void set_Protocol(enum protocol_types  p);
void gfree_all( void );
bool file_exist_stat(const char *fname,SMB_STRUCT_STAT *sbuf,
		     bool fake_dir_create_times);
bool socket_exist(const char *fname);
uint64_t get_file_size_stat(const SMB_STRUCT_STAT *sbuf);
bool check_same_dev_ino(const SMB_STRUCT_STAT *sbuf1,
			const SMB_STRUCT_STAT *sbuf2);
bool check_same_stat(const SMB_STRUCT_STAT *sbuf1,
			const SMB_STRUCT_STAT *sbuf2);
void show_msg(const char *buf);
int set_message_bcc(char *buf,int num_bytes);
ssize_t message_push_blob(uint8_t **outbuf, DATA_BLOB blob);
char *unix_clean_name(TALLOC_CTX *ctx, const char *s);
char *clean_name(TALLOC_CTX *ctx, const char *s);
ssize_t write_data_at_offset(int fd, const char *buffer, size_t N, off_t pos);
NTSTATUS init_before_fork(void);
int parent_watch_fd(void);
NTSTATUS reinit_after_fork(struct messaging_context *msg_ctx,
			   struct tevent_context *ev_ctx,
			   bool parent_longlived);
NTSTATUS smbd_reinit_after_fork(struct messaging_context *msg_ctx,
				struct tevent_context *ev_ctx,
				bool parent_longlived);
void *malloc_(size_t size);
void *Realloc(void *p, size_t size, bool free_old_on_error);
void add_to_large_array(TALLOC_CTX *mem_ctx, size_t element_size,
			void *element, void *_array, uint32_t *num_elements,
			ssize_t *array_size);
char *get_myname(TALLOC_CTX *ctx);
char *get_mydnsdomname(TALLOC_CTX *ctx);
char *automount_lookup(TALLOC_CTX *ctx, const char *user_name);
char *automount_lookup(TALLOC_CTX *ctx, const char *user_name);
bool process_exists(const struct server_id pid);
const char *uidtoname(uid_t uid);
char *gidtoname(gid_t gid);
uid_t nametouid(const char *name);
gid_t nametogid(const char *name);
void smb_panic_s3(const char *why);
void log_panic_action(const char *msg);
const char *readdirname(DIR *p);
bool is_in_path(const char *name,
		struct name_compare_entry *namelist,
		bool case_sensitive);
bool token_contains_name(TALLOC_CTX *mem_ctx,
			 const char *username,
			 const char *domain,
			 const char *sharename,
			 const struct security_token *token,
			 const char *name,
			 bool *match);
bool append_to_namearray(TALLOC_CTX *mem_ctx,
			 const char *namelist_in,
			 struct name_compare_entry **_name_array);
bool set_namearray(TALLOC_CTX *mem_ctx,
		   const char *namelist,
		   struct name_compare_entry **_name_array);
bool fcntl_lock(int fd, int op, off_t offset, off_t count, int type);
bool fcntl_getlock(int fd, int op, off_t *poffset, off_t *pcount, int *ptype, pid_t *ppid);
int map_process_lock_to_ofd_lock(int op);
bool is_myname(const char *s);
void ra_lanman_string( const char *native_lanman );
const char *get_remote_arch_str(void);
enum remote_arch_types get_remote_arch_from_str(const char *remote_arch_string);
void set_remote_arch(enum remote_arch_types type);
enum remote_arch_types get_remote_arch(void);
bool remote_arch_cache_update(const struct GUID *client_guid);
bool remote_arch_cache_delete(const struct GUID *client_guid);
int str_checksum(const char *s);
void zero_free(void *p, size_t size);
int set_maxfiles(int requested_max);
void *smb_xmalloc_array(size_t size, unsigned int count);
char *myhostname(void);
char *myhostname_upper(void);
#include "lib/util_path.h"
bool parent_dirname(TALLOC_CTX *mem_ctx, const char *dir, char **parent,
		    const char **name);
bool ms_has_wild(const char *s);
bool ms_has_wild_w(const smb_ucs2_t *s);
bool mask_match(const char *string, const char *pattern, bool is_case_sensitive);
bool mask_match_list(const char *string, char **list, int listLen, bool is_case_sensitive);
#include "lib/util/unix_match.h"

#include "lib/util_procid.h"

struct server_id interpret_pid(const char *pid_string);
bool is_offset_safe(const char *buf_base, size_t buf_len, char *ptr, size_t off);
char *get_safe_str_ptr(const char *buf_base, size_t buf_len, char *ptr, size_t off);
bool split_domain_user(TALLOC_CTX *mem_ctx,
		       const char *full_name,
		       char **domain,
		       char **user);
const char *strip_hostname(const char *s);
bool any_nt_status_not_ok(NTSTATUS err1, NTSTATUS err2, NTSTATUS *result);
int timeval_to_msec(struct timeval t);
char *valid_share_pathname(TALLOC_CTX *ctx, const char *dos_pathname);
bool is_executable(const char *fname);
bool map_open_params_to_ntcreate(const char *smb_base_fname,
				 int deny_mode, int open_func,
				 uint32_t *paccess_mask,
				 uint32_t *pshare_mode,
				 uint32_t *pcreate_disposition,
				 uint32_t *pcreate_options,
				 uint32_t *pprivate_flags);
struct security_unix_token *copy_unix_token(TALLOC_CTX *ctx, const struct security_unix_token *tok);
struct security_unix_token *root_unix_token(TALLOC_CTX *mem_ctx);
char *utok_string(TALLOC_CTX *mem_ctx, const struct security_unix_token *tok);
bool dir_check_ftype(uint32_t mode, uint32_t dirtype);

/* The following definitions come from lib/util_builtin.c  */

bool lookup_builtin_rid(TALLOC_CTX *mem_ctx, uint32_t rid, const char **name);
bool lookup_builtin_name(const char *name, uint32_t *rid);
const char *builtin_domain_name(void);
bool sid_check_is_builtin(const struct dom_sid *sid);
bool sid_check_is_in_builtin(const struct dom_sid *sid);
bool sid_check_is_wellknown_builtin(const struct dom_sid *sid);

/* The following definitions come from lib/util_nscd.c  */

void smb_nscd_flush_user_cache(void);
void smb_nscd_flush_group_cache(void);

/* The following definitions come from lib/util_nttoken.c  */

NTSTATUS merge_with_system_token(TALLOC_CTX *mem_ctx,
				 const struct security_token *token_1,
				 struct security_token **token_out);
bool token_sid_in_ace(const struct security_token *token, const struct security_ace *ace);

/* The following definitions come from lib/util_sec.c  */

void sec_init(void);
uid_t sec_initial_uid(void);
gid_t sec_initial_gid(void);
bool root_mode(void);
bool non_root_mode(void);
void gain_root_privilege(void);
void gain_root_group_privilege(void);
void set_effective_uid(uid_t uid);
void set_effective_gid(gid_t gid);
void save_re_uid(void);
void restore_re_uid_fromroot(void);
void restore_re_uid(void);
void save_re_gid(void);
void restore_re_gid(void);
int set_re_uid(void);
void become_user_permanently(uid_t uid, gid_t gid);
int set_thread_credentials(uid_t uid,
			gid_t gid,
			size_t setlen,
			const gid_t *gidset);
bool is_setuid_root(void) ;

/* The following definitions come from lib/util_sid.c  */

char *sid_to_fstring(fstring sidstr_out, const struct dom_sid *sid);
bool sid_linearize(uint8_t *outbuf, size_t len, const struct dom_sid *sid);
bool non_mappable_sid(struct dom_sid *sid);
char *sid_binstring_hex_talloc(TALLOC_CTX *mem_ctx, const struct dom_sid *sid);
struct netr_SamInfo3;
NTSTATUS sid_array_from_info3(TALLOC_CTX *mem_ctx,
			      const struct netr_SamInfo3 *info3,
			      struct dom_sid **user_sids,
			      uint32_t *num_user_sids,
			      bool include_user_group_rid);
bool security_token_find_npa_flags(const struct security_token *token,
				   uint32_t *_flags);
void security_token_del_npa_flags(struct security_token *token);

/* The following definitions come from lib/util_sock.c  */

bool is_broadcast_addr(const struct sockaddr *pss);
bool is_loopback_ip_v4(struct in_addr ip);
bool is_loopback_addr(const struct sockaddr *pss);
bool is_zero_addr(const struct sockaddr_storage *pss);
void zero_ip_v4(struct in_addr *ip);
void in_addr_to_sockaddr_storage(struct sockaddr_storage *ss,
		struct in_addr ip);
bool same_net(const struct sockaddr *ip1,
		const struct sockaddr *ip2,
		const struct sockaddr *mask);
bool sockaddr_equal(const struct sockaddr *ip1,
		const struct sockaddr *ip2);
bool is_address_any(const struct sockaddr *psa);
uint16_t get_sockaddr_port(const struct sockaddr_storage *pss);
char *print_sockaddr(char *dest,
			size_t destlen,
			const struct sockaddr_storage *psa);
char *print_canonical_sockaddr(TALLOC_CTX *ctx,
			const struct sockaddr_storage *pss);
bool is_a_socket(int fd);
void set_socket_options(int fd, const char *options);
NTSTATUS read_fd_with_timeout(int fd, char *buf,
				  size_t mincnt, size_t maxcnt,
				  unsigned int time_out,
				  size_t *size_ret);
NTSTATUS read_data_ntstatus(int fd, char *buffer, size_t N);

NTSTATUS read_smb_length_return_keepalive(int fd, char *inbuf,
					  unsigned int timeout,
					  size_t *len);
NTSTATUS receive_smb_raw(int fd,
			char *buffer,
			size_t buflen,
			unsigned int timeout,
			size_t maxlen,
			size_t *p_len);
int open_socket_in_protocol(
	int type,
	int protocol,
	const struct sockaddr_storage *paddr,
	uint16_t port,
	bool rebind);
int open_socket_in(
	int type,
	const struct sockaddr_storage *paddr,
	uint16_t port,
	bool rebind);
NTSTATUS open_socket_out(const struct sockaddr_storage *pss, uint16_t port,
			 int timeout, int *pfd);
struct tevent_req *open_socket_out_send(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					int protocol,
					const struct sockaddr_storage *pss,
					uint16_t port,
					int timeout);
NTSTATUS open_socket_out_recv(struct tevent_req *req, int *pfd);
struct tevent_req *open_socket_out_defer_send(TALLOC_CTX *mem_ctx,
					      struct tevent_context *ev,
					      struct timeval wait_time,
					      const struct sockaddr_storage *pss,
					      uint16_t port,
					      int timeout);
NTSTATUS open_socket_out_defer_recv(struct tevent_req *req, int *pfd);
const char *get_peer_addr(int fd, char *addr, size_t addr_len);

struct tsocket_address;

int get_remote_hostname(const struct tsocket_address *remote_address,
			char **name,
			TALLOC_CTX *mem_ctx);

int create_pipe_sock(const char *socket_dir,
		     const char *socket_name,
		     mode_t dir_perms);
const char *get_mydnsfullname(void);
bool is_myname_or_ipaddr(const char *s);
int poll_one_fd(int fd, int events, int timeout, int *revents);
int poll_intr_one_fd(int fd, int events, int timeout, int *revents);

/* The following definitions come from lib/util_str.c  */

bool strnequal(const char *s1,const char *s2,size_t n);
bool strcsequal(const char *s1,const char *s2);
char *skip_string(const char *base, size_t len, char *buf);
size_t str_charnum(const char *s);
bool trim_char(char *s,char cfront,char cback);
bool strhasupper(const char *s);
bool strhaslower(const char *s);
bool in_list(const char *s, const char *list, bool casesensitive);
char *realloc_string_sub2(char *string,
			const char *pattern,
			const char *insert,
			bool remove_unsafe_characters,
			bool allow_trailing_dollar);
char *realloc_string_sub(char *string,
			const char *pattern,
			const char *insert);
void all_string_sub(char *s,const char *pattern,const char *insert, size_t len);
char *string_truncate(char *s, unsigned int length);
bool strlower_m(char *s);
bool strupper_m(char *s);
int fstr_sprintf(fstring s, const char *fmt, ...);

uint64_t STR_TO_SMB_BIG_UINT(const char *nptr, const char **entptr);
uint64_t conv_str_size(const char * str);
char *talloc_asprintf_strupper_m(TALLOC_CTX *t, const char *fmt, ...)
				 PRINTF_ATTRIBUTE(2,3);
char *talloc_asprintf_strlower_m(TALLOC_CTX *t, const char *fmt, ...)
				 PRINTF_ATTRIBUTE(2,3);
bool validate_net_name( const char *name,
		const char *invalid_chars,
		int max_len);
char *escape_shell_string(const char *src);
ssize_t full_path_tos(const char *dir, const char *name,
		      char *tmpbuf, size_t tmpbuf_len,
		      char **pdst, char **to_free);

/* The following definitions come from lib/version.c  */

const char *samba_version_string(void);
const char *samba_copyright_string(void);

/* The following definitions come from lib/wins_srv.c  */

bool wins_srv_is_dead(struct in_addr wins_ip, struct in_addr src_ip);
void wins_srv_alive(struct in_addr wins_ip, struct in_addr src_ip);
void wins_srv_died(struct in_addr wins_ip, struct in_addr src_ip);
unsigned wins_srv_count(void);
char **wins_srv_tags(void);
void wins_srv_tags_free(char **list);
struct in_addr wins_srv_ip_tag(const char *tag, struct in_addr src_ip);
bool wins_server_tag_ips(const char *tag, TALLOC_CTX *mem_ctx,
			 struct in_addr **pservers, size_t *pnum_servers);
unsigned wins_srv_count_tag(const char *tag);

/* The following definitions come from libsmb/conncache.c  */

NTSTATUS check_negative_conn_cache( const char *domain, const char *server);
void add_failed_connection_entry(const char *domain, const char *server, NTSTATUS result) ;
void flush_negative_conn_cache_for_domain(const char *domain);

/* The following definitions come from libsmb/errormap.c  */

NTSTATUS dos_to_ntstatus(uint8_t eclass, uint32_t ecode);
NTSTATUS map_nt_error_from_wbcErr(wbcErr wbc_err);

/* The following definitions come from libsmb/namecache.c  */

bool namecache_store(const char *name,
			int name_type,
			size_t num_names,
			struct samba_sockaddr *sa_list);
bool namecache_fetch(TALLOC_CTX *ctx,
			const char *name,
			int name_type,
			struct samba_sockaddr **sa_list,
			size_t *num_names);
bool namecache_delete(const char *name, int name_type);
void namecache_flush(void);
bool namecache_status_store(const char *keyname, int keyname_type,
		int name_type, const struct sockaddr_storage *keyip,
		const char *srvname);
bool namecache_status_fetch(const char *keyname,
				int keyname_type,
				int name_type,
				const struct sockaddr_storage *keyip,
				char *srvname_out);

/* The following definitions come from libsmb/namequery_dc.c  */

bool get_dc_name(const char *domain,
		const char *realm,
		fstring srv_name,
		struct sockaddr_storage *ss_out);

/* The following definitions come from libsmb/smberr.c  */

const char *smb_dos_err_name(uint8_t e_class, uint16_t num);
const char *get_dos_error_msg(WERROR result);
const char *smb_dos_err_class(uint8_t e_class);
WERROR map_werror_from_unix(int error);

/* The following definitions come from libsmb/trusts_util.c  */

struct netlogon_creds_cli_context;
struct messaging_context;
struct dcerpc_binding_handle;
char *trust_pw_new_value(TALLOC_CTX *mem_ctx,
			 enum netr_SchannelType sec_channel_type,
			 int security);
NTSTATUS trust_pw_change(struct netlogon_creds_cli_context *context,
			 struct messaging_context *msg_ctx,
			 struct dcerpc_binding_handle *b,
			 const char *domain,
			 const char *dcname,
			 bool force);

/* The following definitions come from lib/sessionid_tdb.c  */
struct sessionid;
NTSTATUS sessionid_traverse_read(int (*fn)(const char *key,
					   struct sessionid *session,
					   void *private_data),
				 void *private_data);

/* The following definitions come from lib/avahi.c */

struct AvahiPoll *tevent_avahi_poll(TALLOC_CTX *mem_ctx,
				    struct tevent_context *ev);

/* The following definitions come from libsmb/smbsock_connect.c */

struct tevent_req *smbsock_connect_send(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					const struct sockaddr_storage *addr,
					uint16_t port,
					const char *called_name,
					int called_type,
					const char *calling_name,
					int calling_type);
NTSTATUS smbsock_connect_recv(struct tevent_req *req, int *sock,
			      uint16_t *ret_port);
NTSTATUS smbsock_connect(const struct sockaddr_storage *addr, uint16_t port,
			 const char *called_name, int called_type,
			 const char *calling_name, int calling_type,
			 int *pfd, uint16_t *ret_port, int sec_timeout);

struct tevent_req *smbsock_any_connect_send(TALLOC_CTX *mem_ctx,
					    struct tevent_context *ev,
					    const struct sockaddr_storage *addrs,
					    const char **called_names,
					    int *called_types,
					    const char **calling_names,
					    int *calling_types,
					    size_t num_addrs, uint16_t port);
NTSTATUS smbsock_any_connect_recv(struct tevent_req *req, int *pfd,
				  size_t *chosen_index, uint16_t *chosen_port);
NTSTATUS smbsock_any_connect(const struct sockaddr_storage *addrs,
			     const char **called_names,
			     int *called_types,
			     const char **calling_names,
			     int *calling_types,
			     size_t num_addrs,
			     uint16_t port,
			     int sec_timeout,
			     int *pfd, size_t *chosen_index,
			     uint16_t *chosen_port);

/* The following definitions come from lib/util_wellknown.c  */

bool sid_check_is_wellknown_domain(const struct dom_sid *sid, const char **name);
bool sid_check_is_in_wellknown_domain(const struct dom_sid *sid);
bool lookup_wellknown_sid(TALLOC_CTX *mem_ctx, const struct dom_sid *sid,
			  const char **domain, const char **name);
bool lookup_wellknown_name(TALLOC_CTX *mem_ctx, const char *name,
			   struct dom_sid *sid, const char **domain);

/* The following definitions come from lib/filename_util.c */

NTSTATUS get_full_smb_filename(TALLOC_CTX *ctx, const struct smb_filename *smb_fname,
			      char **full_name);
struct smb_filename *synthetic_smb_fname(TALLOC_CTX *mem_ctx,
					 const char *base_name,
					 const char *stream_name,
					 const SMB_STRUCT_STAT *psbuf,
					 NTTIME twrp,
					 uint32_t flags);
NTSTATUS safe_symlink_target_path(TALLOC_CTX *mem_ctx,
				  const char *connectpath,
				  const char *dir,
				  const char *target,
				  size_t unparsed,
				  char **_relative);
struct reparse_data_buffer;
NTSTATUS
filename_convert_dirfsp_nosymlink(TALLOC_CTX *mem_ctx,
				  connection_struct *conn,
				  struct files_struct *basedir,
				  const char *name_in,
				  uint32_t ucf_flags,
				  NTTIME twrp,
				  struct files_struct **_dirfsp,
				  struct smb_filename **_smb_fname,
				  struct smb_filename **_smb_fname_rel,
				  struct reparse_data_buffer **_symlink_err);
NTSTATUS filename_convert_dirfsp_rel(TALLOC_CTX *mem_ctx,
				     connection_struct *conn,
				     struct files_struct *basedir,
				     const char *name_in,
				     uint32_t ucf_flags,
				     NTTIME twrp,
				     struct files_struct **_dirfsp,
				     struct smb_filename **_smb_fname,
				     struct smb_filename **_smb_fname_rel);
NTSTATUS filename_convert_dirfsp(
	TALLOC_CTX *ctx,
	connection_struct *conn,
	const char *name_in,
	uint32_t ucf_flags,
	NTTIME twrp,
	struct files_struct **pdirfsp,
	struct smb_filename **psmb_name_rel);
char *full_path_from_dirfsp_at_basename(TALLOC_CTX *mem_ctx,
					const struct files_struct *dirfsp,
					const char *at_base_name);
struct smb_filename *full_path_from_dirfsp_atname(
	TALLOC_CTX *mem_ctx,
	const struct files_struct *dirfsp,
	const struct smb_filename *atname);
struct smb_filename *synthetic_smb_fname_split(TALLOC_CTX *ctx,
						const char *fname,
						bool posix_path);
const char *smb_fname_str_dbg(const struct smb_filename *smb_fname);
const char *fsp_str_dbg(const struct files_struct *fsp);
const char *fsp_fnum_dbg(const struct files_struct *fsp);
struct smb_filename *cp_smb_filename(TALLOC_CTX *mem_ctx,
				     const struct smb_filename *in);
struct smb_filename *cp_smb_filename_nostream(TALLOC_CTX *mem_ctx,
				     const struct smb_filename *in);
bool is_ntfs_stream_smb_fname(const struct smb_filename *smb_fname);
bool is_ntfs_default_stream_smb_fname(const struct smb_filename *smb_fname);
bool is_named_stream(const struct smb_filename *smb_fname);
bool is_invalid_windows_ea_name(const char *name);
bool ea_list_has_invalid_name(struct ea_list *ea_list);
bool split_stream_filename(TALLOC_CTX *ctx,
			const char *filename_in,
			char **filename_out,
			char **streamname_out);

/* The following definitions come from lib/dummyroot.c */

void become_root(void);
void unbecome_root(void);

/* The following definitions come from lib/smbd_shim.c */

int find_service(TALLOC_CTX *ctx, const char *service_in, char **p_service_out);
bool lp_allow_local_address(
	int snum, const struct tsocket_address *local_address);
bool change_to_root_user(void);
bool become_authenticated_pipe_user(struct auth_session_info *session_info);
bool unbecome_authenticated_pipe_user(void);

void contend_level2_oplocks_begin(files_struct *fsp,
				  enum level2_contention_type type);
void contend_level2_oplocks_end(files_struct *fsp,
				enum level2_contention_type type);

/* The following definitions come from lib/per_thread_cwd.c */

void per_thread_cwd_check(void);
bool per_thread_cwd_supported(void);
void per_thread_cwd_disable(void);
void per_thread_cwd_activate(void);

#endif /*  _PROTO_H_  */
