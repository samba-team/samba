/*
 *
 * Unix SMB/CIFS implementation.
 *
 * Type definitions for loadparm
 *
 * Copyright (c) 2020      Andreas Schneider <asn@samba.org>
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _S3_LOADPARM_H
#define _S3_LOADPARM_H

#include <talloc.h>
#include <regex.h>

/* Forward declarations */
typedef struct stat_ex SMB_STRUCT_STAT;
typedef struct files_struct files_struct;
struct smbd_server_connection;
struct security_descriptor;
struct loadparm_context;

/* The following definitions come from param/loadparm.c  */

void loadparm_s3_init_globals(struct loadparm_context *lp_ctx,
			      bool reinit_globals);

const struct loadparm_substitution *loadparm_s3_global_substitution(void);

char *lp_parm_substituted_string(TALLOC_CTX *mem_ctx,
				 const struct loadparm_substitution *lp_sub,
				 int snum,
				 const char *type,
				 const char *option,
				 const char *def);

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
enum credentials_use_kerberos lp_client_use_kerberos(void);
int lp_smb2_max_credits(void);
int lp_cups_encrypt(void);
bool lp_widelinks(int );
int lp_rpc_low_port(void);
int lp_rpc_high_port(void);
const char *lp_dns_hostname(void);
bool lp_lanman_auth(void);
enum samba_weak_crypto lp_weak_crypto(void);
bool lp_strict_rename(int snum);
int lp_smb3_directory_leases(void);

int lp_wi_scan_global_parametrics(
	const char *regex, size_t max_matches,
	bool (*cb)(const char *string, regmatch_t matches[],
		   void *private_data),
	void *private_data);
int lp_wi_scan_share_parametrics(int snum,
				 const char *regex_str,
				 size_t max_matches,
				 bool (*cb)(const char *string,
					    regmatch_t matches[],
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
bool lp_load_with_registry_without_shares(const char *pszFname);
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
struct smb1_signing_state;
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
uint32_t lp_get_async_dns_timeout(void);

/* The following definitions come from param/loadparm_ctx.c  */

const struct loadparm_s3_helpers *loadparm_s3_helpers(void);

/* The following definitions come from param/loadparm_server_role.c  */

int lp_server_role(void);
void set_server_role(void);

/* The following definitions come from param/util.c  */

uint32_t get_int_param( const char* param );
char *get_string_param( const char* param );

#endif /* _S3_LOADPARM_H */
