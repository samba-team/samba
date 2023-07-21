/*
 * Copyright (c) 2020      Andreas Schneider <asn@samba.org>
 *
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

#ifndef _CMDLINE_H
#define _CMDLINE_H

#include "auth/credentials/credentials.h"
#include <popt.h>

#ifndef POPT_TABLEEND
#define POPT_TABLEEND { \
	.longName   = NULL, \
	.shortName  = 0, \
	.argInfo    = 0, \
	.arg        = NULL, \
	.val        = 0, \
	.descrip    = NULL, \
	.argDescrip = NULL }
#endif

enum samba_cmdline_config_type {
	SAMBA_CMDLINE_CONFIG_NONE = 0,
	SAMBA_CMDLINE_CONFIG_CLIENT,
	SAMBA_CMDLINE_CONFIG_SERVER,
};

enum smb_cmdline_popt_options {
	SAMBA_CMDLINE_POPT_OPT_DEBUG_ONLY = 1,
	SAMBA_CMDLINE_POPT_OPT_OPTION_ONLY,
	SAMBA_CMDLINE_POPT_OPT_CONFIG_ONLY,
	SAMBA_CMDLINE_POPT_OPT_SAMBA,
	SAMBA_CMDLINE_POPT_OPT_CONNECTION,
	SAMBA_CMDLINE_POPT_OPT_CREDENTIALS,
	SAMBA_CMDLINE_POPT_OPT_VERSION,
	SAMBA_CMDLINE_POPT_OPT_DAEMON,
	SAMBA_CMDLINE_POPT_OPT_SAMBA_LDB,
	SAMBA_CMDLINE_POPT_OPT_LEGACY_S3,
	SAMBA_CMDLINE_POPT_OPT_LEGACY_S4,
};

struct samba_cmdline_daemon_cfg {
	bool daemon;
	bool interactive;
	bool fork;
	bool no_process_group;
};

/**
 * @brief Initialize the commandline interface for parsing options.
 *
 * This initializes the interface for parsing options given on the command
 * line. It sets up the loadparm and client credentials contexts.
 * The function will also setup fault handler, set logging to STDERR by
 * default, setup talloc logging and the panic handler.
 *
 * The function also setups a callback for loading the smb.conf file, the
 * config file will be parsed after the commandline options have been parsed
 * by popt. This is done by one of the following options parser:
 *
 *     POPT_COMMON_DEBUG_ONLY
 *     POPT_COMMON_OPTION_ONLY
 *     POPT_COMMON_CONFIG_ONLY
 *     POPT_COMMON_SAMBA
 *
 * @param[in]  mem_ctx  The talloc memory context to use for allocating memory.
 *                      This should be a long living context till the client
 *                      exits.
 *
 * @param[in]  require_smbconf  Whether the smb.conf file is required to be
 *                              present or not?
 *
 * @return true on success, false if an error occurred.
 */
bool samba_cmdline_init(TALLOC_CTX *mem_ctx,
			enum samba_cmdline_config_type config_type,
			bool require_smbconf);

/**
 * @brief Get a pointer of loadparm context used for the command line interface.
 *
 * @return The loadparm context.
 */
struct loadparm_context *samba_cmdline_get_lp_ctx(void);

/**
 * @brief Get the client credentials of the command line interface.
 *
 * @return A pointer to the client credentials.
 */
struct cli_credentials *samba_cmdline_get_creds(void);

/**
 * @brief Get a pointer to the poptOption for the given option section.
 *
 * You should not directly use this function, but the macros.
 *
 * @param[in]  opt  The options to retrieve.
 *
 * @return A pointer to the poptOption array.
 *
 * @see POPT_COMMON_DEBUG_ONLY
 * @see POPT_COMMON_OPTION_ONLY
 * @see POPT_COMMON_CONFIG_ONLY
 * @see POPT_COMMON_SAMBA
 * @see POPT_COMMON_CONNECTION
 * @see POPT_COMMON_CREDENTIALS
 * @see POPT_COMMON_VERSION
 */
struct poptOption *samba_cmdline_get_popt(enum smb_cmdline_popt_options opt);

/**
 * @brief Get a pointer to the poptOptions for daemons
 *
 * @return A pointer to the daemon options
 *
 * @see POPT_COMMON_DAEMON
 */
struct samba_cmdline_daemon_cfg *samba_cmdline_get_daemon_cfg(void);

void samba_cmdline_set_machine_account_fn(
	NTSTATUS (*fn) (struct cli_credentials *cred,
			struct loadparm_context *lp_ctx));

/**
 * @brief Burn secrets on the command line.
 *
 * This function removes secrets from the command line so we don't leak e.g.
 * passwords on 'ps aux' output.
 *
 * It should be called after processing the options and you should pass down
 * argv from main().
 *
 * @param[in]  argc     The number of arguments.
 *
 * @param[in]  argv[]   The argument array we should remove secrets from.
 *
 * @return true if a password was removed, false otherwise.
 */
bool samba_cmdline_burn(int argc, char *argv[]);

/**
 * @brief Sanity check the command line options.
 *
 * This checks for duplicates in short and long options.
 *
 * @param[in]  opts    The options array to check.
 *
 * @return true if valid, false otherwise.
 */
bool samba_cmdline_sanity_check(const struct poptOption *opts);

/**
 * @brief This is a wrapper for the poptGetContext() which initializes the popt
 *        context.
 *
 * If Samba is build in developer mode, this will call
 * samba_cmdline_sanity_check() before poptGetContext().
 *
 * @param[in] name     The context name (usually argv[0] program name or
 *                     getprogname())
 *
 * @param[in] argc     Number of arguments
 *
 * @param[in] argv     The argument array
 *
 * @param[in] options  The address of popt option table
 *
 * @param[in] flags    The OR'd POPT_CONTEXT_* bits
 *
 * @return The initialized popt context or NULL on error.
 */
poptContext samba_popt_get_context(const char * name,
				   int argc, const char ** argv,
				   const struct poptOption * options,
				   unsigned int flags);

/**
 * @brief A popt structure for common debug options only.
 */
#define POPT_COMMON_DEBUG_ONLY { \
	.longName   = NULL, \
	.shortName  = '\0', \
	.argInfo    = POPT_ARG_INCLUDE_TABLE, \
	.arg        = samba_cmdline_get_popt(SAMBA_CMDLINE_POPT_OPT_DEBUG_ONLY), \
	.val        = 0, \
	.descrip    = "Common debug options:", \
	.argDescrip = NULL },

/**
 * @brief A popt structure for --option only.
 */
#define POPT_COMMON_OPTION_ONLY { \
	.longName   = NULL, \
	.shortName  = '\0', \
	.argInfo    = POPT_ARG_INCLUDE_TABLE, \
	.arg        = samba_cmdline_get_popt(SAMBA_CMDLINE_POPT_OPT_OPTION_ONLY), \
	.val        = 0, \
	.descrip    = "Options:", \
	.argDescrip = NULL },

/**
 * @brief A popt structure for --configfile only.
 */
#define POPT_COMMON_CONFIG_ONLY { \
	.longName   = NULL, \
	.shortName  = '\0', \
	.argInfo    = POPT_ARG_INCLUDE_TABLE, \
	.arg        = samba_cmdline_get_popt(SAMBA_CMDLINE_POPT_OPT_CONFIG_ONLY), \
	.val        = 0, \
	.descrip    = "Config file:", \
	.argDescrip = NULL },

/**
 * @brief A popt structure for common samba options.
 */
#define POPT_COMMON_SAMBA { \
	.longName   = NULL, \
	.shortName  = '\0', \
	.argInfo    = POPT_ARG_INCLUDE_TABLE, \
	.arg        = samba_cmdline_get_popt(SAMBA_CMDLINE_POPT_OPT_SAMBA), \
	.val        = 0, \
	.descrip    = "Common Samba options:", \
	.argDescrip = NULL },

/**
 * @brief A popt structure for connection options.
 */
#define POPT_COMMON_CONNECTION { \
	.longName   = NULL, \
	.shortName  = '\0', \
	.argInfo    = POPT_ARG_INCLUDE_TABLE, \
	.arg        = samba_cmdline_get_popt(SAMBA_CMDLINE_POPT_OPT_CONNECTION), \
	.val        = 0, \
	.descrip    = "Connection options:", \
	.argDescrip = NULL },

/**
 * @brief A popt structure for credential options.
 */
#define POPT_COMMON_CREDENTIALS { \
	.longName   = NULL, \
	.shortName  = '\0', \
	.argInfo    = POPT_ARG_INCLUDE_TABLE, \
	.arg        = samba_cmdline_get_popt(SAMBA_CMDLINE_POPT_OPT_CREDENTIALS), \
	.val        = 0, \
	.descrip    = "Credential options:", \
	.argDescrip = NULL },

/**
 * @brief A popt structure for version options.
 */
#define POPT_COMMON_VERSION { \
	.longName   = NULL, \
	.shortName  = '\0', \
	.argInfo    = POPT_ARG_INCLUDE_TABLE, \
	.arg        = samba_cmdline_get_popt(SAMBA_CMDLINE_POPT_OPT_VERSION), \
	.val        = 0, \
	.descrip    = "Version options:", \
	.argDescrip = NULL },

/**
 * @brief A popt structure for daemon options.
 */
#define POPT_COMMON_DAEMON { \
	.longName   = NULL, \
	.shortName  = '\0', \
	.argInfo    = POPT_ARG_INCLUDE_TABLE, \
	.arg        = samba_cmdline_get_popt(SAMBA_CMDLINE_POPT_OPT_DAEMON), \
	.val        = 0, \
	.descrip    = "Daemon options:", \
	.argDescrip = NULL },

/**
 * @brief A popt structure for common samba options.
 */
#define POPT_COMMON_SAMBA_LDB { \
	.longName   = NULL, \
	.shortName  = '\0', \
	.argInfo    = POPT_ARG_INCLUDE_TABLE, \
	.arg        = samba_cmdline_get_popt(SAMBA_CMDLINE_POPT_OPT_SAMBA_LDB), \
	.val        = 0, \
	.descrip    = "Common Samba options:", \
	.argDescrip = NULL },

/* TODO Get rid of me! */
#define POPT_LEGACY_S3 { \
	.longName   = NULL, \
	.shortName  = '\0', \
	.argInfo    = POPT_ARG_INCLUDE_TABLE, \
	.arg        = samba_cmdline_get_popt(SAMBA_CMDLINE_POPT_OPT_LEGACY_S3), \
	.val        = 0, \
	.descrip    = "Deprecated legacy options:", \
	.argDescrip = NULL },

/* TODO Get rid of me! */
#define POPT_LEGACY_S4 { \
	.longName   = NULL, \
	.shortName  = '\0', \
	.argInfo    = POPT_ARG_INCLUDE_TABLE, \
	.arg        = samba_cmdline_get_popt(SAMBA_CMDLINE_POPT_OPT_LEGACY_S4), \
	.val        = 0, \
	.descrip    = "Deprecated legacy options:", \
	.argDescrip = NULL },

#endif /* _CMDLINE_H */
