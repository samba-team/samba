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

/* The following definitions come from lib/adt_tree.c  */

/* The following definitions come from lib/audit.c  */

const char *audit_category_str(uint32_t category);
const char *audit_param_str(uint32_t category);
const char *audit_description_str(uint32_t category);
bool get_audit_category_from_param(const char *param, uint32_t *audit_category);
const char *audit_policy_str(TALLOC_CTX *mem_ctx, uint32_t policy);

/* The following definitions come from lib/charcnv.c  */

void gfree_charcnv(void);
size_t ucs2_align(const void *base_ptr, const void *p, int flags);
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
int map_errno_from_nt_status(NTSTATUS status);

/* The following definitions come from lib/file_id.c  */

struct file_id vfs_file_id_from_sbuf(connection_struct *conn, const SMB_STRUCT_STAT *sbuf);

NTSTATUS vfs_at_fspcwd(TALLOC_CTX *mem_ctx,
		       struct connection_struct *conn,
		       struct files_struct **_fsp);

/* The following definitions come from lib/interface.c  */

bool ismyaddr(const struct sockaddr *ip);
bool ismyip_v4(struct in_addr ip);
bool is_local_net(const struct sockaddr *from);
void setup_linklocal_scope_id(struct sockaddr *pss);
bool is_local_net_v4(struct in_addr from);
int iface_count(void);
int iface_count_v4_nl(void);
const struct in_addr *first_ipv4_iface(void);
struct interface *get_interface(int n);
const struct sockaddr_storage *iface_n_sockaddr_storage(int n);
const struct in_addr *iface_n_ip_v4(int n);
const struct in_addr *iface_n_bcast_v4(int n);
const struct sockaddr_storage *iface_n_bcast(int n);
const struct sockaddr_storage *iface_ip(const struct sockaddr *ip);
bool iface_local(const struct sockaddr *ip);
void load_interfaces(void);
void gfree_interfaces(void);
bool interfaces_changed(void);

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
struct security_descriptor *get_share_security_default( TALLOC_CTX *ctx, size_t *psize, uint32_t def_access);
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

/* The following definitions come from lib/substitute.c  */

bool set_local_machine_name(const char *local_name, bool perm);
const char *get_local_machine_name(void);
bool set_remote_machine_name(const char *remote_name, bool perm);
const char *get_remote_machine_name(void);
void sub_set_smb_name(const char *name);
void set_current_user_info(const char *smb_name, const char *unix_name,
			   const char *domain);
void sub_set_socket_ids(const char *peeraddr, const char *peername,
			const char *sockaddr);
const char *get_current_username(void);
void standard_sub_basic(const char *smb_name, const char *domain_name,
			char *str, size_t len);
char *talloc_sub_basic(TALLOC_CTX *mem_ctx, const char *smb_name,
		       const char *domain_name, const char *str);
char *talloc_sub_specified(TALLOC_CTX *mem_ctx,
			const char *input_string,
			const char *username,
			const char *grpname,
			const char *domain,
			uid_t uid,
			gid_t gid);
char *talloc_sub_advanced(TALLOC_CTX *mem_ctx,
			  const char *servicename, const char *user,
			  const char *connectpath, gid_t gid,
			  const char *str);
char *talloc_sub_full(TALLOC_CTX *mem_ctx,
			  const char *servicename, const char *user,
			  const char *connectpath, gid_t gid,
			  const char *smb_name, const char *domain_name,
			  const char *str);

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
void update_stat_ex_itime(struct stat_ex *dst, struct timespec itime);
void update_stat_ex_create_time(struct stat_ex *dst, struct timespec create_time);
void update_stat_ex_file_id(struct stat_ex *dst, uint64_t file_id);
void update_stat_ex_from_saved_stat(struct stat_ex *dst,
				    const struct stat_ex *src);
int sys_stat(const char *fname, SMB_STRUCT_STAT *sbuf,
	     bool fake_dir_create_times);
int sys_fstat(int fd, SMB_STRUCT_STAT *sbuf,
	      bool fake_dir_create_times);
int sys_lstat(const char *fname,SMB_STRUCT_STAT *sbuf,
	      bool fake_dir_create_times);
int sys_posix_fallocate(int fd, off_t offset, off_t len);
int sys_fallocate(int fd, uint32_t mode, off_t offset, off_t len);
void kernel_flock(int fd, uint32_t share_access, uint32_t access_mask);
DIR *sys_fdopendir(int fd);
int sys_mknod(const char *path, mode_t mode, SMB_DEV_T dev);
int sys_mknodat(int dirfd, const char *path, mode_t mode, SMB_DEV_T dev);
char *sys_getwd(void);
void set_effective_capability(enum smbd_capability capability);
void drop_effective_capability(enum smbd_capability capability);
long sys_random(void);
void sys_srandom(unsigned int seed);
int groups_max(void);
int sys_getgroups(int setlen, gid_t *gidset);
int sys_setgroups(gid_t UNUSED(primary_gid), int setlen, gid_t *gidset);
uint32_t unix_dev_major(SMB_DEV_T dev);
uint32_t unix_dev_minor(SMB_DEV_T dev);
char *sys_realpath(const char *path);
#if 0
int sys_get_number_of_cores(void);
#endif

struct stat;
void init_stat_ex_from_stat (struct stat_ex *dst,
			    const struct stat *src,
			    bool fake_dir_create_times);

/* The following definitions come from lib/system_smbd.c  */

bool getgroups_unix_user(TALLOC_CTX *mem_ctx, const char *user,
			 gid_t primary_gid,
			 gid_t **ret_groups, uint32_t *p_ngroups);

/* The following definitions come from lib/tallocmsg.c  */

void register_msg_pool_usage(TALLOC_CTX *mem_ctx,
			     struct messaging_context *msg_ctx);

/* The following definitions come from lib/time.c  */

void push_dos_date(uint8_t *buf, int offset, time_t unixdate, int zone_offset);
void push_dos_date2(uint8_t *buf,int offset,time_t unixdate, int zone_offset);
void push_dos_date3(uint8_t *buf,int offset,time_t unixdate, int zone_offset);
uint32_t convert_time_t_to_uint32_t(time_t t);
time_t convert_uint32_t_to_time_t(uint32_t u);
bool nt_time_is_zero(const NTTIME *nt);
time_t generalized_to_unix_time(const char *str);
int get_server_zone_offset(void);
int set_server_zone_offset(time_t t);
char *timeval_string(TALLOC_CTX *ctx, const struct timeval *tp, bool hires);
char *current_timestring(TALLOC_CTX *ctx, bool hires);
void srv_put_dos_date(char *buf,int offset,time_t unixdate);
void srv_put_dos_date2(char *buf,int offset, time_t unixdate);
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
struct timespec interpret_long_date(const char *p);
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

enum protocol_types get_Protocol(void);
void set_Protocol(enum protocol_types  p);
void gfree_names(void);
void gfree_all( void );
const char *my_netbios_names(int i);
bool set_netbios_aliases(const char **str_array);
bool init_names(void);
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
NTSTATUS reinit_after_fork(struct messaging_context *msg_ctx,
			   struct tevent_context *ev_ctx,
			   bool parent_longlived,
			   const char *comment);
NTSTATUS smbd_reinit_after_fork(struct messaging_context *msg_ctx,
				struct tevent_context *ev_ctx,
				bool parent_longlived,
				const char *comment);
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
const char *readdirname(DIR *p);
bool is_in_path(const char *name, name_compare_entry *namelist, bool case_sensitive);
void set_namearray(name_compare_entry **ppname_array, const char *namelist);
void free_namearray(name_compare_entry *name_array);
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
const char *tab_depth(int level, int depth);
int str_checksum(const char *s);
void zero_free(void *p, size_t size);
int set_maxfiles(int requested_max);
int smb_mkstemp(char *name_template);
void *smb_xmalloc_array(size_t size, unsigned int count);
char *myhostname(void);
char *myhostname_upper(void);
#include "lib/util_path.h"
bool parent_dirname(TALLOC_CTX *mem_ctx, const char *dir, char **parent,
		    const char **name);
bool parent_smb_fname(TALLOC_CTX *mem_ctx,
		      const struct smb_filename *path,
		      struct smb_filename **_parent,
		      struct smb_filename  **_name);
bool ms_has_wild(const char *s);
bool ms_has_wild_w(const smb_ucs2_t *s);
bool mask_match(const char *string, const char *pattern, bool is_case_sensitive);
bool mask_match_search(const char *string, const char *pattern, bool is_case_sensitive);
bool mask_match_list(const char *string, char **list, int listLen, bool is_case_sensitive);
#include "lib/util/unix_match.h"
bool name_to_fqdn(fstring fqdn, const char *name);
uint32_t map_share_mode_to_deny_mode(uint32_t share_access, uint32_t private_options);

#include "lib/util_procid.h"

struct server_id interpret_pid(const char *pid_string);
bool is_offset_safe(const char *buf_base, size_t buf_len, char *ptr, size_t off);
char *get_safe_ptr(const char *buf_base, size_t buf_len, char *ptr, size_t off);
char *get_safe_str_ptr(const char *buf_base, size_t buf_len, char *ptr, size_t off);
int get_safe_SVAL(const char *buf_base, size_t buf_len, char *ptr, size_t off, int failval);
int get_safe_IVAL(const char *buf_base, size_t buf_len, char *ptr, size_t off, int failval);
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

struct security_token *dup_nt_token(TALLOC_CTX *mem_ctx, const struct security_token *ptoken);
NTSTATUS merge_nt_token(TALLOC_CTX *mem_ctx,
			const struct security_token *token_1,
			const struct security_token *token_2,
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
int get_socket_port(int fd);
const char *client_addr(int fd, char *addr, size_t addrlen);
const char *client_socket_addr(int fd, char *addr, size_t addr_len);
int client_socket_port(int fd);
bool is_a_socket(int fd);
void set_socket_options(int fd, const char *options);
ssize_t read_udp_v4_socket(int fd,
			char *buf,
			size_t len,
			struct sockaddr_storage *psa);
NTSTATUS read_fd_with_timeout(int fd, char *buf,
				  size_t mincnt, size_t maxcnt,
				  unsigned int time_out,
				  size_t *size_ret);
NTSTATUS read_data_ntstatus(int fd, char *buffer, size_t N);

bool send_keepalive(int client);
NTSTATUS read_smb_length_return_keepalive(int fd, char *inbuf,
					  unsigned int timeout,
					  size_t *len);
NTSTATUS receive_smb_raw(int fd,
			char *buffer,
			size_t buflen,
			unsigned int timeout,
			size_t maxlen,
			size_t *p_len);
int open_socket_in(int type,
		uint16_t port,
		int dlevel,
		const struct sockaddr_storage *psock,
		bool rebind);
NTSTATUS open_socket_out(const struct sockaddr_storage *pss, uint16_t port,
			 int timeout, int *pfd);
struct tevent_req *open_socket_out_send(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
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
int open_udp_socket(const char *host, int port);
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

bool next_token(const char **ptr, char *buff, const char *sep, size_t bufsize);
bool strnequal(const char *s1,const char *s2,size_t n);
bool strcsequal(const char *s1,const char *s2);
bool strnorm(char *s, int case_default);
char *skip_string(const char *base, size_t len, char *buf);
size_t str_charnum(const char *s);
bool trim_char(char *s,char cfront,char cback);
bool strhasupper(const char *s);
bool strhaslower(const char *s);
bool in_list(const char *s, const char *list, bool casesensitive);
void fstring_sub(char *s,const char *pattern,const char *insert);
char *realloc_string_sub2(char *string,
			const char *pattern,
			const char *insert,
			bool remove_unsafe_characters,
			bool allow_trailing_dollar);
char *realloc_string_sub(char *string,
			const char *pattern,
			const char *insert);
char *talloc_string_sub2(TALLOC_CTX *mem_ctx, const char *src,
			const char *pattern,
			const char *insert,
			bool remove_unsafe_characters,
			bool replace_once,
			bool allow_trailing_dollar);
char *talloc_string_sub(TALLOC_CTX *mem_ctx,
			const char *src,
			const char *pattern,
			const char *insert);
void all_string_sub(char *s,const char *pattern,const char *insert, size_t len);
char *talloc_all_string_sub(TALLOC_CTX *ctx,
				const char *src,
				const char *pattern,
				const char *insert);
char *octal_string(int i);
char *string_truncate(char *s, unsigned int length);
char *strchr_m(const char *src, char c);
char *strrchr_m(const char *s, char c);
char *strnrchr_m(const char *s, char c, unsigned int n);
char *strstr_m(const char *src, const char *findstr);
bool strlower_m(char *s);
bool strupper_m(char *s);
size_t strlen_m(const char *s);
size_t strlen_m_term(const char *s);
size_t strlen_m_term_null(const char *s);
int fstr_sprintf(fstring s, const char *fmt, ...);

char *ipstr_list_make(char **ipstr_list,
			const struct ip_service *ip_list,
			int ip_count);
int ipstr_list_parse(const char *ipstr_list, struct ip_service **ip_list);
void ipstr_list_free(char* ipstr_list);
uint64_t STR_TO_SMB_BIG_UINT(const char *nptr, const char **entptr);
uint64_t conv_str_size(const char * str);
int asprintf_strupper_m(char **strp, const char *fmt, ...)
			PRINTF_ATTRIBUTE(2,3);
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

/* The following definitions come from lib/wins_srv.c  */

bool wins_srv_is_dead(struct in_addr wins_ip, struct in_addr src_ip);
void wins_srv_alive(struct in_addr wins_ip, struct in_addr src_ip);
void wins_srv_died(struct in_addr wins_ip, struct in_addr src_ip);
unsigned wins_srv_count(void);
char **wins_srv_tags(void);
void wins_srv_tags_free(char **list);
struct in_addr wins_srv_ip_tag(const char *tag, struct in_addr src_ip);
bool wins_server_tag_ips(const char *tag, TALLOC_CTX *mem_ctx,
			 struct in_addr **pservers, int *pnum_servers);
unsigned wins_srv_count_tag(const char *tag);

#ifndef ASN1_MAX_OIDS
#define ASN1_MAX_OIDS 20
#endif
bool spnego_parse_negTokenInit(TALLOC_CTX *ctx,
			       DATA_BLOB blob,
			       char *OIDs[ASN1_MAX_OIDS],
			       char **principal,
			       DATA_BLOB *secblob);
DATA_BLOB spnego_gen_krb5_wrap(TALLOC_CTX *ctx, const DATA_BLOB ticket, const uint8_t tok_id[2]);

/* The following definitions come from libsmb/conncache.c  */

NTSTATUS check_negative_conn_cache( const char *domain, const char *server);
void add_failed_connection_entry(const char *domain, const char *server, NTSTATUS result) ;
void flush_negative_conn_cache_for_domain(const char *domain);

/* The following definitions come from libsmb/errormap.c  */

NTSTATUS dos_to_ntstatus(uint8_t eclass, uint32_t ecode);

/* The following definitions come from libsmb/namecache.c  */

bool namecache_store(const char *name,
			int name_type,
			int num_names,
			struct ip_service *ip_list);
bool namecache_fetch(const char *name,
			int name_type,
			struct ip_service **ip_list,
			int *num_names);
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

/* The following definitions come from param/loadparm.c  */

const struct loadparm_substitution *loadparm_s3_global_substitution(void);

char *lp_parm_substituted_string(TALLOC_CTX *mem_ctx,
				 const struct loadparm_substitution *lp_sub,
				 int snum,
				 const char *type,
				 const char *option,
				 const char *def);

#include "source3/param/param_proto.h"

char *lp_servicename(TALLOC_CTX *ctx, const struct loadparm_substitution *, int);
const char *lp_const_servicename(int);
bool lp_autoloaded(int);
const char *lp_dnsdomain(void);
int lp_winbind_max_domain_connections(void);
bool lp_idmap_range(const char *domain_name, uint32_t *low, uint32_t *high);
bool lp_idmap_default_range(uint32_t *low, uint32_t *high);
const char *lp_idmap_backend(const char *domain_name);
const char *lp_idmap_default_backend (void);
int lp_security(void);
int lp_client_max_protocol(void);
int lp_client_ipc_min_protocol(void);
int lp_client_ipc_max_protocol(void);
int lp_client_ipc_signing(void);
int lp_smb2_max_credits(void);
int lp_cups_encrypt(void);
bool lp_widelinks(int );
int lp_rpc_low_port(void);
int lp_rpc_high_port(void);
bool lp_lanman_auth(void);
enum samba_weak_crypto lp_weak_crypto(void);

int lp_wi_scan_global_parametrics(
	const char *regex, size_t max_matches,
	bool (*cb)(const char *string, regmatch_t matches[],
		   void *private_data),
	void *private_data);

const char *lp_parm_const_string(int snum, const char *type, const char *option, const char *def);
struct loadparm_service;
const char *lp_parm_const_string_service(struct loadparm_service *service, const char *type,
					 const char *option, const char *def);
const char **lp_parm_string_list(int snum, const char *type, const char *option, const char **def);
int lp_parm_int(int snum, const char *type, const char *option, int def);
unsigned long lp_parm_ulong(int snum, const char *type, const char *option, unsigned long def);
unsigned long long lp_parm_ulonglong(int snum, const char *type,
				     const char *option,
				     unsigned long long def);
bool lp_parm_bool(int snum, const char *type, const char *option, bool def);
struct enum_list;
int lp_parm_enum(int snum, const char *type, const char *option,
		 const struct enum_list *_enum, int def);
char *canonicalize_servicename(TALLOC_CTX *ctx, const char *src);
bool lp_add_home(const char *pszHomename, int iDefaultService,
		 const char *user, const char *pszHomedir);
int lp_add_service(const char *pszService, int iDefaultService);
bool lp_add_printer(const char *pszPrintername, int iDefaultService);
bool lp_parameter_is_valid(const char *pszParmName);
bool lp_parameter_is_global(const char *pszParmName);
bool lp_canonicalize_parameter(const char *parm_name, const char **canon_parm,
			       bool *inverse);
bool lp_canonicalize_parameter_with_value(const char *parm_name,
					  const char *val,
					  const char **canon_parm,
					  const char **canon_val);
void show_parameter_list(void);
bool lp_invert_boolean(const char *str, const char **inverse_str);
bool lp_canonicalize_boolean(const char *str, const char**canon_str);
bool process_registry_service(const char *service_name);
bool process_registry_shares(void);
bool lp_config_backend_is_registry(void);
bool lp_config_backend_is_file(void);
bool lp_file_list_changed(void);
const char *lp_ldap_machine_suffix(TALLOC_CTX *ctx);
const char *lp_ldap_user_suffix(TALLOC_CTX *ctx);
const char *lp_ldap_group_suffix(TALLOC_CTX *ctx);
const char *lp_ldap_idmap_suffix(TALLOC_CTX *ctx);
struct parm_struct;
/* Return a pointer to a service by name.  */
struct loadparm_service *lp_service(const char *pszServiceName);
struct loadparm_service *lp_servicebynum(int snum);
struct loadparm_service *lp_default_loadparm_service(void);
void *lp_parm_ptr(struct loadparm_service *service, struct parm_struct *parm);
void *lp_local_ptr_by_snum(int snum, struct parm_struct *parm);
bool lp_do_parameter(int snum, const char *pszParmName, const char *pszParmValue);
bool lp_set_cmdline(const char *pszParmName, const char *pszParmValue);
bool dump_a_parameter(int snum, char *parm_name, FILE * f, bool isGlobal);
bool lp_snum_ok(int iService);
void lp_add_one_printer(const char *name, const char *comment,
			const char *location, void *pdata);
bool lp_loaded(void);
void lp_killunused(struct smbd_server_connection *sconn,
		   bool (*snumused) (struct smbd_server_connection *, int));
void lp_kill_all_services(void);
void lp_killservice(int iServiceIn);
const char* server_role_str(uint32_t role);
enum usershare_err parse_usershare_file(TALLOC_CTX *ctx,
			SMB_STRUCT_STAT *psbuf,
			const char *servicename,
			int snum,
			char **lines,
			int numlines,
			char **pp_sharepath,
			char **pp_comment,
			char **pp_cp_share_name,
			struct security_descriptor **ppsd,
			bool *pallow_guest);
int load_usershare_service(const char *servicename);
int load_usershare_shares(struct smbd_server_connection *sconn,
			  bool (*snumused) (struct smbd_server_connection *, int));
void gfree_loadparm(void);
bool lp_load_initial_only(const char *pszFname);
bool lp_load_global(const char *file_name);
bool lp_load_with_shares(const char *file_name);
bool lp_load_client(const char *file_name);
bool lp_load_global_no_reinit(const char *file_name);
bool lp_load_no_reinit(const char *file_name);
bool lp_load_client_no_reinit(const char *file_name);
bool lp_load_with_registry_shares(const char *pszFname);
int lp_numservices(void);
void lp_dump(FILE *f, bool show_defaults, int maxtoprint);
void lp_dump_one(FILE * f, bool show_defaults, int snum);
int lp_servicenumber(const char *pszServiceName);
const char *volume_label(TALLOC_CTX *ctx, int snum);
bool lp_domain_master(void);
bool lp_preferred_master(void);
void lp_remove_service(int snum);
void lp_copy_service(int snum, const char *new_name);
int lp_default_server_announce(void);
const char *lp_printername(TALLOC_CTX *ctx,
			   const struct loadparm_substitution *lp_sub,
			   int snum);
void lp_set_logfile(const char *name);
int lp_maxprintjobs(int snum);
const char *lp_printcapname(void);
bool lp_disable_spoolss( void );
void lp_set_spoolss_state( uint32_t state );
uint32_t lp_get_spoolss_state( void );
struct smb_signing_state;
void set_use_sendfile(int snum, bool val);
void lp_set_mangling_method(const char *new_method);
bool lp_posix_pathnames(void);
void lp_set_posix_pathnames(void);
enum brl_flavour lp_posix_cifsu_locktype(files_struct *fsp);
void lp_set_posix_default_cifsx_readwrite_locktype(enum brl_flavour val);
int lp_min_receive_file_size(void);
void widelinks_warning(int snum);
const char *lp_ncalrpc_dir(void);
void _lp_set_server_role(int server_role);

/* The following definitions come from param/loadparm_ctx.c  */

const struct loadparm_s3_helpers *loadparm_s3_helpers(void);

/* The following definitions come from param/loadparm_server_role.c  */

int lp_server_role(void);
void set_server_role(void);

/* The following definitions come from param/util.c  */

uint32_t get_int_param( const char* param );
char* get_string_param( const char* param );

/* The following definitions come from lib/server_contexts.c  */
struct tevent_context *global_event_context(void);
void global_event_context_free(void);
struct messaging_context *global_messaging_context(void);
void global_messaging_context_free(void);

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

/* The following definitions come from lib/util_specialsids.c  */
bool sid_check_is_asserted_identity(const struct dom_sid *sid);
bool sid_check_is_in_asserted_identity(const struct dom_sid *sid);
const char *asserted_identity_domain_name(void);

/* The following definitions come from lib/filename_util.c */

NTSTATUS get_full_smb_filename(TALLOC_CTX *ctx, const struct smb_filename *smb_fname,
			      char **full_name);
struct smb_filename *synthetic_smb_fname(TALLOC_CTX *mem_ctx,
					 const char *base_name,
					 const char *stream_name,
					 const SMB_STRUCT_STAT *psbuf,
					 NTTIME twrp,
					 uint32_t flags);
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
void send_stat_cache_delete_message(struct messaging_context *msg_ctx,
				    const char *name);
NTSTATUS can_delete_directory_fsp(files_struct *fsp);
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
