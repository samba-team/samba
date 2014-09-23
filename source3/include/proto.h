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

/* The following definitions come from lib/access.c  */

bool client_match(const char *tok, const void *item);
bool list_match(const char **list,const void *item,
		bool (*match_fn)(const char *, const void *));
bool allow_access(const char **deny_list,
		const char **allow_list,
		const char *cname,
		const char *caddr);

/* The following definitions come from lib/adt_tree.c  */

/* The following definitions come from lib/audit.c  */

const char *audit_category_str(uint32 category);
const char *audit_param_str(uint32 category);
const char *audit_description_str(uint32 category);
bool get_audit_category_from_param(const char *param, uint32 *audit_category);
const char *audit_policy_str(TALLOC_CTX *mem_ctx, uint32 policy);

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
size_t push_string_base(const char *base, uint16 flags2,
			void *dest, const char *src,
			size_t dest_len, int flags);
size_t pull_string_talloc(TALLOC_CTX *ctx,
			const void *base_ptr,
			uint16 smb_flags2,
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

/* The following definitions come from lib/gencache.c  */

bool gencache_set(const char *keystr, const char *value, time_t timeout);
bool gencache_del(const char *keystr);
bool gencache_get(const char *keystr, TALLOC_CTX *mem_ctx, char **value,
		  time_t *ptimeout);
bool gencache_parse(const char *keystr,
		    void (*parser)(time_t timeout, DATA_BLOB blob,
				   void *private_data),
		    void *private_data);
bool gencache_get_data_blob(const char *keystr, TALLOC_CTX *mem_ctx,
			    DATA_BLOB *blob,
			    time_t *timeout, bool *was_expired);
bool gencache_stabilize(void);
bool gencache_set_data_blob(const char *keystr, const DATA_BLOB *blob, time_t timeout);
void gencache_iterate_blobs(void (*fn)(const char *key, DATA_BLOB value,
				       time_t timeout, void *private_data),
			    void *private_data, const char *pattern);
void gencache_iterate(void (*fn)(const char* key, const char *value, time_t timeout, void* dptr),
                      void* data, const char* keystr_pattern);

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

bool share_info_db_init(void);
struct security_descriptor *get_share_security_default( TALLOC_CTX *ctx, size_t *psize, uint32 def_access);
struct security_descriptor *get_share_security( TALLOC_CTX *ctx, const char *servicename,
			      size_t *psize);
bool set_share_security(const char *share_name, struct security_descriptor *psd);
bool delete_share_security(const char *servicename);
bool share_access_check(const struct security_token *token,
			const char *sharename,
			uint32 desired_access,
			uint32_t *pgranted);
bool parse_usershare_acl(TALLOC_CTX *ctx, const char *acl_str, struct security_descriptor **ppsd);

/* The following definitions come from lib/smbrun.c  */

int smbrun_no_sanitize(const char *cmd, int *outfd);
int smbrun(const char *cmd, int *outfd);
int smbrunsecret(const char *cmd, const char *secret);

/* The following definitions come from lib/sock_exec.c  */

int sock_exec(const char *prog);

/* The following definitions come from lib/substitute.c  */

void free_local_machine_name(void);
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
			  const char *smb_name, const char *domain_name,
			  const char *str);
void standard_sub_advanced(const char *servicename, const char *user,
			   const char *connectpath, gid_t gid,
			   const char *smb_name, const char *domain_name,
			   char *str, size_t len);

/* The following definitions come from lib/sysquotas.c  */

int sys_get_quota(const char *path, enum SMB_QUOTA_TYPE qtype, unid_t id, SMB_DISK_QUOTA *dp);
int sys_set_quota(const char *path, enum SMB_QUOTA_TYPE qtype, unid_t id, SMB_DISK_QUOTA *dp);

/* The following definitions come from lib/sysquotas_*.c  */

int sys_get_vfs_quota(const char *path, const char *bdev, enum SMB_QUOTA_TYPE qtype, unid_t id, SMB_DISK_QUOTA *dp);
int sys_set_vfs_quota(const char *path, const char *bdev, enum SMB_QUOTA_TYPE qtype, unid_t id, SMB_DISK_QUOTA *dp);

int sys_get_xfs_quota(const char *path, const char *bdev, enum SMB_QUOTA_TYPE qtype, unid_t id, SMB_DISK_QUOTA *dp);
int sys_set_xfs_quota(const char *path, const char *bdev, enum SMB_QUOTA_TYPE qtype, unid_t id, SMB_DISK_QUOTA *dp);

int sys_get_nfs_quota(const char *path, const char *bdev,
		      enum SMB_QUOTA_TYPE qtype,
		      unid_t id, SMB_DISK_QUOTA *dp);
int sys_set_nfs_quota(const char *path, const char *bdev,
		      enum SMB_QUOTA_TYPE qtype,
		      unid_t id, SMB_DISK_QUOTA *dp);

/* The following definitions come from lib/system.c  */

ssize_t sys_read(int fd, void *buf, size_t count);
ssize_t sys_write(int fd, const void *buf, size_t count);
ssize_t sys_writev(int fd, const struct iovec *iov, int iovcnt);
ssize_t sys_pread(int fd, void *buf, size_t count, off_t off);
ssize_t sys_pwrite(int fd, const void *buf, size_t count, off_t off);
ssize_t sys_send(int s, const void *msg, size_t len, int flags);
ssize_t sys_recvfrom(int s, void *buf, size_t len, int flags, struct sockaddr *from, socklen_t *fromlen);
int sys_fcntl_ptr(int fd, int cmd, void *arg);
int sys_fcntl_long(int fd, int cmd, long arg);
void update_stat_ex_mtime(struct stat_ex *dst, struct timespec write_ts);
void update_stat_ex_create_time(struct stat_ex *dst, struct timespec create_time);
int sys_stat(const char *fname, SMB_STRUCT_STAT *sbuf,
	     bool fake_dir_create_times);
int sys_fstat(int fd, SMB_STRUCT_STAT *sbuf,
	      bool fake_dir_create_times);
int sys_lstat(const char *fname,SMB_STRUCT_STAT *sbuf,
	      bool fake_dir_create_times);
int sys_posix_fallocate(int fd, off_t offset, off_t len);
int sys_fallocate(int fd, enum vfs_fallocate_mode mode, off_t offset, off_t len);
void kernel_flock(int fd, uint32 share_mode, uint32 access_mask);
DIR *sys_fdopendir(int fd);
int sys_mknod(const char *path, mode_t mode, SMB_DEV_T dev);
int sys_waitpid(pid_t pid,int *status,int options);
char *sys_getwd(void);
void set_effective_capability(enum smbd_capability capability);
void drop_effective_capability(enum smbd_capability capability);
long sys_random(void);
void sys_srandom(unsigned int seed);
int groups_max(void);
int sys_getgroups(int setlen, gid_t *gidset);
int sys_setgroups(gid_t UNUSED(primary_gid), int setlen, gid_t *gidset);
int sys_popen(const char *command);
int sys_pclose(int fd);
ssize_t sys_getxattr (const char *path, const char *name, void *value, size_t size);
ssize_t sys_fgetxattr (int filedes, const char *name, void *value, size_t size);
ssize_t sys_listxattr (const char *path, char *list, size_t size);
ssize_t sys_flistxattr (int filedes, char *list, size_t size);
int sys_removexattr (const char *path, const char *name);
int sys_fremovexattr (int filedes, const char *name);
int sys_setxattr (const char *path, const char *name, const void *value, size_t size, int flags);
int sys_fsetxattr (int filedes, const char *name, const void *value, size_t size, int flags);
uint32 unix_dev_major(SMB_DEV_T dev);
uint32 unix_dev_minor(SMB_DEV_T dev);
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

void register_msg_pool_usage(struct messaging_context *msg_ctx);

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
time_t uint64s_nt_time_to_unix_abs(const uint64_t *src);
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

/* The following definitions come from lib/util.c  */

enum protocol_types get_Protocol(void);
void set_Protocol(enum protocol_types  p);
bool all_zero(const uint8_t *ptr, size_t size);
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
ssize_t message_push_blob(uint8 **outbuf, DATA_BLOB blob);
char *unix_clean_name(TALLOC_CTX *ctx, const char *s);
char *clean_name(TALLOC_CTX *ctx, const char *s);
ssize_t write_data_at_offset(int fd, const char *buffer, size_t N, off_t pos);
int set_blocking(int fd, bool set);
NTSTATUS init_before_fork(void);
NTSTATUS reinit_after_fork(struct messaging_context *msg_ctx,
			   struct tevent_context *ev_ctx,
			   bool parent_longlived);
void *malloc_(size_t size);
void *Realloc(void *p, size_t size, bool free_old_on_error);
void add_to_large_array(TALLOC_CTX *mem_ctx, size_t element_size,
			void *element, void *_array, uint32 *num_elements,
			ssize_t *array_size);
char *get_myname(TALLOC_CTX *ctx);
char *get_mydnsdomname(TALLOC_CTX *ctx);
char *automount_lookup(TALLOC_CTX *ctx, const char *user_name);
char *automount_lookup(TALLOC_CTX *ctx, const char *user_name);
bool process_exists(const struct server_id pid);
bool processes_exist(const struct server_id *pids, int num_pids,
		     bool *results);
const char *uidtoname(uid_t uid);
char *gidtoname(gid_t gid);
uid_t nametouid(const char *name);
gid_t nametogid(const char *name);
void smb_panic_s3(const char *why);
void log_stack_trace(void);
const char *readdirname(DIR *p);
bool is_in_path(const char *name, name_compare_entry *namelist, bool case_sensitive);
void set_namearray(name_compare_entry **ppname_array, const char *namelist);
void free_namearray(name_compare_entry *name_array);
bool fcntl_lock(int fd, int op, off_t offset, off_t count, int type);
bool fcntl_getlock(int fd, off_t *poffset, off_t *pcount, int *ptype, pid_t *ppid);
bool is_myname(const char *s);
void ra_lanman_string( const char *native_lanman );
const char *get_remote_arch_str(void);
void set_remote_arch(enum remote_arch_types type);
enum remote_arch_types get_remote_arch(void);
const char *tab_depth(int level, int depth);
int str_checksum(const char *s);
void zero_free(void *p, size_t size);
int set_maxfiles(int requested_max);
int smb_mkstemp(char *name_template);
void *smb_xmalloc_array(size_t size, unsigned int count);
char *myhostname(void);
char *myhostname_upper(void);
char *lock_path(const char *name);
char *state_path(const char *name);
char *cache_path(const char *name);
bool parent_dirname(TALLOC_CTX *mem_ctx, const char *dir, char **parent,
		    const char **name);
bool ms_has_wild(const char *s);
bool ms_has_wild_w(const smb_ucs2_t *s);
bool mask_match(const char *string, const char *pattern, bool is_case_sensitive);
bool mask_match_search(const char *string, const char *pattern, bool is_case_sensitive);
bool mask_match_list(const char *string, char **list, int listLen, bool is_case_sensitive);
bool unix_wild_match(const char *pattern, const char *string);
bool name_to_fqdn(fstring fqdn, const char *name);
void *talloc_append_blob(TALLOC_CTX *mem_ctx, void *buf, DATA_BLOB blob);
uint32 map_share_mode_to_deny_mode(uint32 share_access, uint32 private_options);
pid_t procid_to_pid(const struct server_id *proc);
void set_my_vnn(uint32 vnn);
uint32 get_my_vnn(void);
void set_my_unique_id(uint64_t unique_id);
struct server_id pid_to_procid(pid_t pid);
struct server_id procid_self(void);
#define serverid_equal(p1, p2) server_id_equal(p1,p2)
bool procid_is_me(const struct server_id *pid);
struct server_id interpret_pid(const char *pid_string);
char *procid_str_static(const struct server_id *pid);
bool procid_valid(const struct server_id *pid);
bool procid_is_local(const struct server_id *pid);
bool is_offset_safe(const char *buf_base, size_t buf_len, char *ptr, size_t off);
char *get_safe_ptr(const char *buf_base, size_t buf_len, char *ptr, size_t off);
char *get_safe_str_ptr(const char *buf_base, size_t buf_len, char *ptr, size_t off);
int get_safe_SVAL(const char *buf_base, size_t buf_len, char *ptr, size_t off, int failval);
int get_safe_IVAL(const char *buf_base, size_t buf_len, char *ptr, size_t off, int failval);
void split_domain_user(TALLOC_CTX *mem_ctx,
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
				 uint32 *paccess_mask,
				 uint32 *pshare_mode,
				 uint32 *pcreate_disposition,
				 uint32 *pcreate_options,
				 uint32_t *pprivate_flags);
struct security_unix_token *copy_unix_token(TALLOC_CTX *ctx, const struct security_unix_token *tok);
bool dir_check_ftype(uint32_t mode, uint32_t dirtype);
void init_modules(void);

/* The following definitions come from lib/util_builtin.c  */

bool lookup_builtin_rid(TALLOC_CTX *mem_ctx, uint32 rid, const char **name);
bool lookup_builtin_name(const char *name, uint32 *rid);
const char *builtin_domain_name(void);
bool sid_check_is_builtin(const struct dom_sid *sid);
bool sid_check_is_in_builtin(const struct dom_sid *sid);
bool sid_check_is_wellknown_builtin(const struct dom_sid *sid);

/* The following definitions come from lib/util_file.c  */

char **file_lines_pload(const char *syscmd, int *numlines);
void file_lines_free(char **lines);

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
char *sid_string_talloc(TALLOC_CTX *mem_ctx, const struct dom_sid *sid);
char *sid_string_dbg(const struct dom_sid *sid);
char *sid_string_tos(const struct dom_sid *sid);
bool sid_linearize(char *outbuf, size_t len, const struct dom_sid *sid);
bool non_mappable_sid(struct dom_sid *sid);
char *sid_binstring_hex(const struct dom_sid *sid);
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
NTSTATUS read_data(int fd, char *buffer, size_t N);
ssize_t write_data(int fd, const char *buffer, size_t N);
ssize_t iov_buflen(const struct iovec *iov, int iovlen);
uint8_t *iov_buf(TALLOC_CTX *mem_ctx, const struct iovec *iov, int iovcnt);
ssize_t write_data_iov(int fd, const struct iovec *orig_iov, int iovcnt);
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
int create_tcpip_socket(const struct sockaddr_storage *ifss, uint16_t *port);
const char *get_mydnsfullname(void);
bool is_myname_or_ipaddr(const char *s);
struct tevent_req *getaddrinfo_send(TALLOC_CTX *mem_ctx,
				    struct tevent_context *ev,
				    struct fncall_context *ctx,
				    const char *node,
				    const char *service,
				    const struct addrinfo *hints);
int getaddrinfo_recv(struct tevent_req *req, struct addrinfo **res);
int poll_one_fd(int fd, int events, int timeout, int *revents);
int poll_intr_one_fd(int fd, int events, int timeout, int *revents);
struct tstream_context;
struct tevent_req *tstream_read_packet_send(TALLOC_CTX *mem_ctx,
					    struct tevent_context *ev,
					    struct tstream_context *stream,
					    size_t initial,
					    ssize_t (*more)(uint8_t *buf,
							    size_t buflen,
							    void *private_data),
					    void *private_data);
ssize_t tstream_read_packet_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
				 uint8_t **pbuf, int *perrno);

/* The following definitions come from lib/util_str.c  */

bool next_token(const char **ptr, char *buff, const char *sep, size_t bufsize);
bool strnequal(const char *s1,const char *s2,size_t n);
bool strcsequal(const char *s1,const char *s2);
bool strnorm(char *s, int case_default);
char *push_skip_string(char *buf);
char *skip_string(const char *base, size_t len, char *buf);
size_t str_charnum(const char *s);
bool trim_char(char *s,char cfront,char cback);
bool strhasupper(const char *s);
bool strhaslower(const char *s);
char *StrnCpy(char *dest,const char *src,size_t n);
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
bool str_list_sub_basic( char **list, const char *smb_name,
			 const char *domain_name );
bool str_list_substitute(char **list, const char *pattern, const char *insert);

char *ipstr_list_make(char **ipstr_list,
			const struct ip_service *ip_list,
			int ip_count);
int ipstr_list_parse(const char *ipstr_list, struct ip_service **ip_list);
void ipstr_list_free(char* ipstr_list);
uint64_t STR_TO_SMB_BIG_UINT(const char *nptr, const char **entptr);
uint64_t conv_str_size(const char * str);
void sprintf_append(TALLOC_CTX *mem_ctx, char **string, ssize_t *len,
		    size_t *bufsize, const char *fmt, ...);
int asprintf_strupper_m(char **strp, const char *fmt, ...);
char *talloc_asprintf_strupper_m(TALLOC_CTX *t, const char *fmt, ...);
char *talloc_asprintf_strlower_m(TALLOC_CTX *t, const char *fmt, ...);
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

/* The following definitions come from libsmb/clispnego.c  */

DATA_BLOB spnego_gen_negTokenInit(TALLOC_CTX *ctx,
				  const char *OIDs[],
				  DATA_BLOB *psecblob,
				  const char *principal);

#ifndef ASN1_MAX_OIDS
#define ASN1_MAX_OIDS 20
#endif
bool spnego_parse_negTokenInit(TALLOC_CTX *ctx,
			       DATA_BLOB blob,
			       char *OIDs[ASN1_MAX_OIDS],
			       char **principal,
			       DATA_BLOB *secblob);
DATA_BLOB spnego_gen_krb5_wrap(TALLOC_CTX *ctx, const DATA_BLOB ticket, const uint8 tok_id[2]);
int spnego_gen_krb5_negTokenInit(TALLOC_CTX *ctx,
			    const char *principal, int time_offset,
			    DATA_BLOB *targ,
			    DATA_BLOB *session_key_krb5, uint32 extra_ap_opts,
			    const char *ccname, time_t *expire_time);
bool spnego_parse_challenge(TALLOC_CTX *ctx, const DATA_BLOB blob,
			    DATA_BLOB *chal1, DATA_BLOB *chal2);
DATA_BLOB spnego_gen_auth(TALLOC_CTX *ctx, DATA_BLOB blob);
bool spnego_parse_auth_response(TALLOC_CTX *ctx,
				DATA_BLOB blob, NTSTATUS nt_status,
				const char *mechOID,
				DATA_BLOB *auth);

/* The following definitions come from libsmb/conncache.c  */

NTSTATUS check_negative_conn_cache( const char *domain, const char *server);
void add_failed_connection_entry(const char *domain, const char *server, NTSTATUS result) ;
void flush_negative_conn_cache_for_domain(const char *domain);

/* The following definitions come from libsmb/dsgetdcname.c  */

struct netr_DsRGetDCNameInfo;

void debug_dsdcinfo_flags(int lvl, uint32_t flags);
NTSTATUS dsgetdcname(TALLOC_CTX *mem_ctx,
		     struct messaging_context *msg_ctx,
		     const char *domain_name,
		     const struct GUID *domain_guid,
		     const char *site_name,
		     uint32_t flags,
		     struct netr_DsRGetDCNameInfo **info);

/* The following definitions come from libsmb/errormap.c  */

NTSTATUS dos_to_ntstatus(uint8 eclass, uint32 ecode);

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

/* The following definitions come from libsmb/namequery.c  */

bool saf_store( const char *domain, const char *servername );
bool saf_join_store( const char *domain, const char *servername );
bool saf_delete( const char *domain );
char *saf_fetch(TALLOC_CTX *mem_ctx, const char *domain );
struct tevent_req *node_status_query_send(TALLOC_CTX *mem_ctx,
					  struct tevent_context *ev,
					  struct nmb_name *name,
					  const struct sockaddr_storage *addr);
NTSTATUS node_status_query_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
				struct node_status **pnode_status,
				int *pnum_names,
				struct node_status_extra *extra);
NTSTATUS node_status_query(TALLOC_CTX *mem_ctx, struct nmb_name *name,
			   const struct sockaddr_storage *addr,
			   struct node_status **pnode_status,
			   int *pnum_names,
			   struct node_status_extra *extra);
bool name_status_find(const char *q_name,
			int q_type,
			int type,
			const struct sockaddr_storage *to_ss,
			fstring name);
int ip_service_compare(struct ip_service *ss1, struct ip_service *ss2);
int remove_duplicate_addrs2(struct ip_service *iplist, int count );
struct tevent_req *name_query_send(TALLOC_CTX *mem_ctx,
				   struct tevent_context *ev,
				   const char *name, int name_type,
				   bool bcast, bool recurse,
				   const struct sockaddr_storage *addr);
NTSTATUS name_query_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
			 struct sockaddr_storage **addrs, int *num_addrs,
			 uint8_t *flags);
NTSTATUS name_query(const char *name, int name_type,
		    bool bcast, bool recurse,
		    const struct sockaddr_storage *to_ss,
		    TALLOC_CTX *mem_ctx,
		    struct sockaddr_storage **addrs,
		    int *num_addrs, uint8_t *flags);
struct tevent_req *name_resolve_bcast_send(TALLOC_CTX *mem_ctx,
					   struct tevent_context *ev,
					   const char *name,
					   int name_type);
NTSTATUS name_resolve_bcast_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
				 struct sockaddr_storage **addrs,
				 int *num_addrs);
NTSTATUS name_resolve_bcast(const char *name,
			int name_type,
			TALLOC_CTX *mem_ctx,
			struct sockaddr_storage **return_iplist,
			int *return_count);
struct tevent_req *resolve_wins_send(TALLOC_CTX *mem_ctx,
				     struct tevent_context *ev,
				     const char *name,
				     int name_type);
NTSTATUS resolve_wins_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
			   struct sockaddr_storage **addrs,
			   int *num_addrs, uint8_t *flags);
NTSTATUS resolve_wins(const char *name,
		int name_type,
		TALLOC_CTX *mem_ctx,
		struct sockaddr_storage **return_iplist,
		int *return_count);
NTSTATUS internal_resolve_name(const char *name,
			        int name_type,
				const char *sitename,
				struct ip_service **return_iplist,
				int *return_count,
				const char **resolve_order);
bool resolve_name(const char *name,
		struct sockaddr_storage *return_ss,
		int name_type,
		bool prefer_ipv4);
NTSTATUS resolve_name_list(TALLOC_CTX *ctx,
		const char *name,
		int name_type,
		struct sockaddr_storage **return_ss_arr,
		unsigned int *p_num_entries);
bool find_master_ip(const char *group, struct sockaddr_storage *master_ss);
bool get_pdc_ip(const char *domain, struct sockaddr_storage *pss);
NTSTATUS get_sorted_dc_list( const char *domain,
			const char *sitename,
			struct ip_service **ip_list,
			int *count,
			bool ads_only );
NTSTATUS get_kdc_list( const char *realm,
			const char *sitename,
			struct ip_service **ip_list,
			int *count);

/* The following definitions come from libsmb/namequery_dc.c  */

bool get_dc_name(const char *domain,
		const char *realm,
		fstring srv_name,
		struct sockaddr_storage *ss_out);

/* The following definitions come from libsmb/ntlmssp.c  */
struct ntlmssp_state;
NTSTATUS ntlmssp_set_username(struct ntlmssp_state *ntlmssp_state, const char *user) ;
NTSTATUS ntlmssp_set_password(struct ntlmssp_state *ntlmssp_state, const char *password) ;
NTSTATUS ntlmssp_set_password_hash(struct ntlmssp_state *ntlmssp_state,
				   const char *hash);
NTSTATUS ntlmssp_set_domain(struct ntlmssp_state *ntlmssp_state, const char *domain) ;
void ntlmssp_want_feature_list(struct ntlmssp_state *ntlmssp_state, char *feature_list);
void ntlmssp_want_feature(struct ntlmssp_state *ntlmssp_state, uint32_t feature);
NTSTATUS ntlmssp_update(struct ntlmssp_state *ntlmssp_state,
			const DATA_BLOB in, DATA_BLOB *out) ;
bool ntlmssp_is_anonymous(struct ntlmssp_state *ntlmssp_state);
NTSTATUS ntlmssp_server_start(TALLOC_CTX *mem_ctx,
			      bool is_standalone,
			      const char *netbios_name,
			      const char *netbios_domain,
			      const char *dns_name,
			      const char *dns_domain,
			      struct ntlmssp_state **ntlmssp_state);
NTSTATUS ntlmssp_client_start(TALLOC_CTX *mem_ctx,
			      const char *netbios_name,
			      const char *netbios_domain,
			      bool use_ntlmv2,
			      struct ntlmssp_state **_ntlmssp_state);

/* The following definitions come from libsmb/passchange.c  */

NTSTATUS remote_password_change(const char *remote_machine, const char *user_name, 
				const char *old_passwd, const char *new_passwd,
				char **err_str);

/* The following definitions come from libsmb/samlogon_cache.c  */

bool netsamlogon_cache_init(void);
bool netsamlogon_cache_shutdown(void);
void netsamlogon_clear_cached_user(const struct dom_sid *user_sid);
bool netsamlogon_cache_store(const char *username, struct netr_SamInfo3 *info3);
struct netr_SamInfo3 *netsamlogon_cache_get(TALLOC_CTX *mem_ctx, const struct dom_sid *user_sid);
bool netsamlogon_cache_have(const struct dom_sid *user_sid);

/* The following definitions come from libsmb/smberr.c  */

const char *smb_dos_err_name(uint8 e_class, uint16 num);
const char *get_dos_error_msg(WERROR result);
const char *smb_dos_err_class(uint8 e_class);
WERROR map_werror_from_unix(int error);

/* The following definitions come from libsmb/trustdom_cache.c  */

bool trustdom_cache_enable(void);
bool trustdom_cache_shutdown(void);
bool trustdom_cache_store(const char *name, const char *alt_name,
			  const struct dom_sid *sid, time_t timeout);
bool trustdom_cache_fetch(const char* name, struct dom_sid* sid);
uint32 trustdom_cache_fetch_timestamp( void );
bool trustdom_cache_store_timestamp( uint32 t, time_t timeout );
void trustdom_cache_flush(void);
void update_trustdom_cache( void );

/* The following definitions come from libsmb/trusts_util.c  */

struct netlogon_creds_cli_context;
struct messaging_context;
struct dcerpc_binding_handle;
NTSTATUS trust_pw_change(struct netlogon_creds_cli_context *context,
			 struct messaging_context *msg_ctx,
			 struct dcerpc_binding_handle *b,
			 const char *domain,
			 bool force);

/* The following definitions come from param/loadparm.c  */

#include "source3/param/param_proto.h"

char *lp_servicename(TALLOC_CTX *ctx, int);
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
int lp_winbindd_max_protocol(void);
int lp_smb2_max_credits(void);
int lp_cups_encrypt(void);
bool lp_widelinks(int );

char *lp_parm_talloc_string(TALLOC_CTX *ctx, int snum, const char *type, const char *option, const char *def);
const char *lp_parm_const_string(int snum, const char *type, const char *option, const char *def);
struct loadparm_service;
const char *lp_parm_const_string_service(struct loadparm_service *service, const char *type,
					 const char *option, const char *def);
const char **lp_parm_string_list(int snum, const char *type, const char *option, const char **def);
int lp_parm_int(int snum, const char *type, const char *option, int def);
unsigned long lp_parm_ulong(int snum, const char *type, const char *option, unsigned long def);
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
bool lp_parameter_is_canonical(const char *parm_name);
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
const char* server_role_str(uint32 role);
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
bool lp_load(const char *pszFname,
	     bool global_only,
	     bool save_defaults,
	     bool add_ipc,
	     bool initialize_globals);
bool lp_load_initial_only(const char *pszFname);
bool lp_load_global(const char *file_name);
bool lp_load_client(const char *file_name);
bool lp_load_global_no_reinit(const char *file_name);
bool lp_load_client_no_reinit(const char *file_name);
bool lp_load_with_registry_shares(const char *pszFname,
				  bool global_only,
				  bool save_defaults,
				  bool add_ipc,
				  bool initialize_globals);
int lp_numservices(void);
void lp_dump(FILE *f, bool show_defaults, int maxtoprint);
void lp_dump_one(FILE * f, bool show_defaults, int snum);
int lp_servicenumber(const char *pszServiceName);
struct share_params *get_share_params(TALLOC_CTX *mem_ctx,
				      const char *sharename);
const char *volume_label(TALLOC_CTX *ctx, int snum);
bool lp_domain_master(void);
bool lp_preferred_master(void);
void lp_remove_service(int snum);
void lp_copy_service(int snum, const char *new_name);
int lp_default_server_announce(void);
const char *lp_printername(TALLOC_CTX *ctx, int snum);
void lp_set_logfile(const char *name);
int lp_maxprintjobs(int snum);
const char *lp_printcapname(void);
bool lp_disable_spoolss( void );
void lp_set_spoolss_state( uint32 state );
uint32 lp_get_spoolss_state( void );
struct smb_signing_state;
bool lp_use_sendfile(int snum, struct smb_signing_state *signing_state);
void set_use_sendfile(int snum, bool val);
void set_store_dos_attributes(int snum, bool val);
void lp_set_mangling_method(const char *new_method);
bool lp_posix_pathnames(void);
void lp_set_posix_pathnames(void);
enum brl_flavour lp_posix_cifsu_locktype(files_struct *fsp);
void lp_set_posix_default_cifsx_readwrite_locktype(enum brl_flavour val);
int lp_min_receive_file_size(void);
char* lp_perfcount_module(TALLOC_CTX *ctx);
void widelinks_warning(int snum);
const char *lp_ncalrpc_dir(void);
void _lp_set_server_role(int server_role);

/* The following definitions come from param/loadparm_ctx.c  */

const struct loadparm_s3_helpers *loadparm_s3_helpers(void);

/* The following definitions come from param/loadparm_server_role.c  */

int lp_server_role(void);
void set_server_role(void);

/* The following definitions come from param/util.c  */

uint32 get_int_param( const char* param );
char* get_string_param( const char* param );

/* The following definitions come from lib/server_contexts.c  */
struct tevent_context *server_event_context(void);
void server_event_context_free(void);
struct messaging_context *server_messaging_context(void);
void server_messaging_context_free(void);

/* The following definitions come from lib/sessionid_tdb.c  */
struct sessionid;
NTSTATUS sessionid_traverse_read(int (*fn)(const char *key,
					   struct sessionid *session,
					   void *private_data),
				 void *private_data);

/* The following definitions come from utils/passwd_util.c  */

char *stdin_new_passwd( void);
char *get_pass( const char *prompt, bool stdin_get);

/* The following definitions come from lib/avahi.c */

struct AvahiPoll *tevent_avahi_poll(TALLOC_CTX *mem_ctx,
				    struct tevent_context *ev);

/* The following definitions come from lib/fncall.c */

struct fncall_context *fncall_context_init(TALLOC_CTX *mem_ctx,
					   int max_threads);
struct tevent_req *fncall_send(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			       struct fncall_context *ctx,
			       void (*fn)(void *private_data),
			       void *private_data);
int fncall_recv(struct tevent_req *req, int *perr);

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

/* The following definitions come from lib/util_unixsids.c  */

bool sid_check_is_unix_users(const struct dom_sid *sid);
bool sid_check_is_in_unix_users(const struct dom_sid *sid);
void uid_to_unix_users_sid(uid_t uid, struct dom_sid *sid);
void gid_to_unix_groups_sid(gid_t gid, struct dom_sid *sid);
const char *unix_users_domain_name(void);
bool lookup_unix_user_name(const char *name, struct dom_sid *sid);
bool sid_check_is_unix_groups(const struct dom_sid *sid);
bool sid_check_is_in_unix_groups(const struct dom_sid *sid);
const char *unix_groups_domain_name(void);
bool lookup_unix_group_name(const char *name, struct dom_sid *sid);

/* The following definitions come from lib/filename_util.c */

NTSTATUS get_full_smb_filename(TALLOC_CTX *ctx, const struct smb_filename *smb_fname,
			      char **full_name);
struct smb_filename *synthetic_smb_fname(TALLOC_CTX *mem_ctx,
					 const char *base_name,
					 const char *stream_name,
					 const SMB_STRUCT_STAT *psbuf);
struct smb_filename *synthetic_smb_fname_split(TALLOC_CTX *ctx,
					       const char *fname,
					       const SMB_STRUCT_STAT *psbuf);
const char *smb_fname_str_dbg(const struct smb_filename *smb_fname);
const char *fsp_str_dbg(const struct files_struct *fsp);
const char *fsp_fnum_dbg(const struct files_struct *fsp);
struct smb_filename *cp_smb_filename(TALLOC_CTX *mem_ctx,
				     const struct smb_filename *in);
bool is_ntfs_stream_smb_fname(const struct smb_filename *smb_fname);
bool is_ntfs_default_stream_smb_fname(const struct smb_filename *smb_fname);
bool is_invalid_windows_ea_name(const char *name);
bool ea_list_has_invalid_name(struct ea_list *ea_list);

/* The following definitions come from lib/dummyroot.c */

void become_root(void);
void unbecome_root(void);

/* The following definitions come from lib/smbd_shim.c */

int find_service(TALLOC_CTX *ctx, const char *service_in, char **p_service_out);
void cancel_pending_lock_requests_by_fid(files_struct *fsp,
			struct byte_range_lock *br_lck,
			enum file_close_type close_type);
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

#endif /*  _PROTO_H_  */
