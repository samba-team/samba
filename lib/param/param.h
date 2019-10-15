/* 
   Unix SMB/CIFS implementation.
   Generic parameter parsing interface
   Copyright (C) Jelmer Vernooij					  2005
   
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

#ifndef _PARAM_H /* _PARAM_H */
#define _PARAM_H 

struct loadparm_s3_helpers;
struct loadparm_substitution;

struct parmlist_entry;

struct param_context {
	struct param_section *sections;
};

struct param_section {
	const char *name;
	struct param_section *prev, *next;
	struct parmlist *parameters;
};

struct param_context;
struct smbsrv_connection;

#define Auto (2)

struct loadparm_context;
struct loadparm_service;
struct smbcli_options;
struct smbcli_session_options;
struct gensec_settings;
struct bitmap;
struct file_lists;

#ifdef CONFIG_H_IS_FROM_SAMBA
#include "lib/param/param_proto.h"
#include "lib/param/param_functions.h"
#endif

const char **lpcfg_interfaces(struct loadparm_context *);
const char *lpcfg_realm(struct loadparm_context *);
const char *lpcfg_netbios_name(struct loadparm_context *);
const char *lpcfg_private_dir(struct loadparm_context *);
const char *lpcfg_binddns_dir(struct loadparm_context *);
int lpcfg_server_role(struct loadparm_context *);
int lpcfg_allow_dns_updates(struct loadparm_context *);

void reload_charcnv(struct loadparm_context *lp_ctx);

struct loadparm_service *lpcfg_default_service(struct loadparm_context *lp_ctx);
bool lpcfg_autoloaded(struct loadparm_service *, struct loadparm_service *);

char *lpcfg_tls_keyfile(TALLOC_CTX *mem_ctx, struct loadparm_context *);
char *lpcfg_tls_certfile(TALLOC_CTX *mem_ctx, struct loadparm_context *);
char *lpcfg_tls_cafile(TALLOC_CTX *mem_ctx, struct loadparm_context *);
char *lpcfg_tls_dhpfile(TALLOC_CTX *mem_ctx, struct loadparm_context *);
char *lpcfg_tls_crlfile(TALLOC_CTX *mem_ctx, struct loadparm_context *);

const char *lpcfg_dnsdomain(struct loadparm_context *);

const char *lpcfg_servicename(const struct loadparm_service *service);


const char *lpcfg_get_parametric(struct loadparm_context *lp_ctx,
			      struct loadparm_service *service,
			      const char *type, const char *option);

const char *lpcfg_parm_string(struct loadparm_context *lp_ctx,
			   struct loadparm_service *service, const char *type,
			   const char *option);
const char **lpcfg_parm_string_list(TALLOC_CTX *mem_ctx,
				 struct loadparm_context *lp_ctx,
				 struct loadparm_service *service,
				 const char *type,
				 const char *option, const char *separator);
int lpcfg_parm_int(struct loadparm_context *lp_ctx,
		struct loadparm_service *service, const char *type,
		const char *option, int default_v);
int lpcfg_parm_bytes(struct loadparm_context *lp_ctx,
		  struct loadparm_service *service, const char *type,
		  const char *option, int default_v);
unsigned long lpcfg_parm_ulong(struct loadparm_context *lp_ctx,
			    struct loadparm_service *service, const char *type,
			    const char *option, unsigned long default_v);
unsigned long long lpcfg_parm_ulonglong(struct loadparm_context *lp_ctx,
					struct loadparm_service *service,
					const char *type, const char *option,
					unsigned long long default_v);
long lpcfg_parm_long(struct loadparm_context *lp_ctx,
		     struct loadparm_service *service, const char *type,
		     const char *option, long default_v);
double lpcfg_parm_double(struct loadparm_context *lp_ctx,
		      struct loadparm_service *service, const char *type,
		      const char *option, double default_v);
bool lpcfg_parm_bool(struct loadparm_context *lp_ctx,
		     struct loadparm_service *service, const char *type,
		     const char *option, bool default_v);
struct loadparm_service *lpcfg_add_service(struct loadparm_context *lp_ctx,
				     const struct loadparm_service *pservice,
				     const char *name);
bool lpcfg_add_home(struct loadparm_context *lp_ctx,
		 const char *pszHomename,
		 struct loadparm_service *default_service,
		 const char *user, const char *pszHomedir);
bool lpcfg_add_printer(struct loadparm_context *lp_ctx,
		    const char *pszPrintername,
		    struct loadparm_service *default_service);
struct parm_struct *lpcfg_parm_struct(struct loadparm_context *lp_ctx, const char *name);
void *lpcfg_parm_ptr(struct loadparm_context *lp_ctx,
		  struct loadparm_service *service, struct parm_struct *parm);
bool lpcfg_parm_is_cmdline(struct loadparm_context *lp_ctx, const char *name);
bool lpcfg_file_list_changed(struct loadparm_context *lp_ctx);

bool lpcfg_do_global_parameter(struct loadparm_context *lp_ctx,
			    const char *pszParmName, const char *pszParmValue);
bool lpcfg_do_service_parameter(struct loadparm_context *lp_ctx,
			     struct loadparm_service *service,
			     const char *pszParmName, const char *pszParmValue);

/**
 * Process a parameter.
 */
bool lpcfg_do_global_parameter_var(struct loadparm_context *lp_ctx,
				const char *pszParmName, const char *fmt, ...);
bool lpcfg_set_cmdline(struct loadparm_context *lp_ctx, const char *pszParmName,
		    const char *pszParmValue);
bool lpcfg_set_option(struct loadparm_context *lp_ctx, const char *option);

/**
 * Display the contents of a single services record.
 */
bool lpcfg_dump_a_parameter(struct loadparm_context *lp_ctx,
			 struct loadparm_service *service,
			 const char *parm_name, FILE * f);

/**
 * Unload unused services.
 */
void lpcfg_killunused(struct loadparm_context *lp_ctx,
		   struct smbsrv_connection *smb,
		   bool (*snumused) (struct smbsrv_connection *, int));

/**
 * Initialise the global parameter structure.
 */
struct loadparm_context *loadparm_init(TALLOC_CTX *mem_ctx);
struct loadparm_context *loadparm_init_global(bool load_default);
const char *lpcfg_configfile(struct loadparm_context *lp_ctx);
bool lpcfg_load_default(struct loadparm_context *lp_ctx);
const char *lp_default_path(void);

/**
 * Load the services array from the services file.
 *
 * Return True on success, False on failure.
 */
bool lpcfg_load(struct loadparm_context *lp_ctx, const char *filename);

/**
 * Return the max number of services.
 */
int lpcfg_numservices(struct loadparm_context *lp_ctx);

/**
 * Display the contents of the services array in human-readable form.
 */
void lpcfg_dump(struct loadparm_context *lp_ctx, FILE *f, bool show_defaults,
	     int maxtoprint);

/**
 * Display the contents of one service in human-readable form.
 */
void lpcfg_dump_one(FILE *f, bool show_defaults, struct loadparm_service *service, struct loadparm_service *sDefault);
struct loadparm_service *lpcfg_servicebynum(struct loadparm_context *lp_ctx,
					 int snum);
struct loadparm_service *lpcfg_service(struct loadparm_context *lp_ctx,
				    const char *service_name);

/**
 * A useful volume label function.
 */
const char *lp_cfg_volume_label(struct loadparm_service *service, struct loadparm_service *sDefault);

/**
 * If we are PDC then prefer us as DMB
 */
const char *lpcfg_printername(struct loadparm_service *service, struct loadparm_service *sDefault);

/**
 * Return the max print jobs per queue.
 */
int lpcfg_maxprintjobs(struct loadparm_service *service, struct loadparm_service *sDefault);
struct smb_iconv_handle *lpcfg_iconv_handle(struct loadparm_context *lp_ctx);
void lpcfg_smbcli_options(struct loadparm_context *lp_ctx,
			 struct smbcli_options *options);
void lpcfg_smbcli_session_options(struct loadparm_context *lp_ctx,
				 struct smbcli_session_options *options);
const char **lpcfg_smb_ports(struct loadparm_context *);
const char *lpcfg_socket_options(struct loadparm_context *);
struct dcerpc_server_info *lpcfg_dcerpc_server_info(TALLOC_CTX *mem_ctx, struct loadparm_context *lp_ctx);
struct gensec_settings *lpcfg_gensec_settings(TALLOC_CTX *, struct loadparm_context *);

/* The following definitions come from param/util.c  */


/**
 * @file
 * @brief Misc utility functions
 */
bool lpcfg_is_mydomain(struct loadparm_context *lp_ctx,
			     const char *domain);

bool lpcfg_is_my_domain_or_realm(struct loadparm_context *lp_ctx,
			      const char *domain);

/**
  see if a string matches either our primary or one of our secondary 
  netbios aliases. do a case insensitive match
*/
bool lpcfg_is_myname(struct loadparm_context *lp_ctx, const char *name);

/**
 A useful function for returning a path in the Samba lock directory.
**/
char *lpcfg_lock_path(TALLOC_CTX* mem_ctx, struct loadparm_context *lp_ctx,
			 const char *name);

/**
 * @brief Returns an absolute path to a file in the directory containing the current config file
 *
 * @param name File to find, relative to the config file directory.
 *
 * @retval Pointer to a talloc'ed string containing the full path.
 **/
char *lpcfg_config_path(TALLOC_CTX* mem_ctx, struct loadparm_context *lp_ctx,
			   const char *name);

/**
 * @brief Returns an absolute path to a file in the Samba private directory.
 *
 * @param name File to find, relative to PRIVATEDIR.
 * if name is not relative, then use it as-is
 *
 * @retval Pointer to a talloc'ed string containing the full path.
 **/
char *lpcfg_private_path(TALLOC_CTX* mem_ctx,
			    struct loadparm_context *lp_ctx,
			    const char *name);

/**
 * @brief Returns an absolute path to a NTDB or TDB file in the Samba
 * private directory.
 *
 * @param name File to find, relative to PRIVATEDIR, without .tdb extension.
 *
 * @retval Pointer to a talloc'ed string containing the full path, for
 * use with dbwrap_local_open().
 **/
char *lpcfg_private_db_path(TALLOC_CTX *mem_ctx,
			    struct loadparm_context *lp_ctx,
			    const char *name);

/**
  return a path in the smbd.tmp directory, where all temporary file
  for smbd go. If NULL is passed for name then return the directory 
  path itself
*/
char *smbd_tmp_path(TALLOC_CTX *mem_ctx, 
			     struct loadparm_context *lp_ctx,
			     const char *name);

const char *lpcfg_imessaging_path(TALLOC_CTX *mem_ctx,
				       struct loadparm_context *lp_ctx);
const char *lpcfg_sam_name(struct loadparm_context *lp_ctx);
const char *lpcfg_sam_dnsname(struct loadparm_context *lp_ctx);

void lpcfg_default_kdc_policy(TALLOC_CTX *mem_ctx,
				struct loadparm_context *lp_ctx,
				time_t *svc_tkt_lifetime,
				time_t *usr_tkt_lifetime,
				time_t *renewal_lifetime);

int lpcfg_rpc_port_low(struct loadparm_context *lp_ctx);
int lpcfg_rpc_port_high(struct loadparm_context *lp_ctx);

/* The following definitions come from lib/version.c  */

const char *samba_version_string(void);


#endif /* _PARAM_H */
