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
	SAMBA_CMDLINE_CONFIG_CLIENT = 0,
	SAMBA_CMDLINE_CONFIG_SERVER,
};

enum smb_cmdline_popt_options {
	SAMBA_CMDLINE_POPT_OPT_SAMBA = 1,
	SAMBA_CMDLINE_POPT_OPT_CONNECTION,
	SAMBA_CMDLINE_POPT_OPT_CREDENTIALS,
	SAMBA_CMDLINE_POPT_OPT_VERSION,
	SAMBA_CMDLINE_POPT_OPT_SAMBA_LDB,
	SAMBA_CMDLINE_POPT_OPT_LEGACY_S3,
	SAMBA_CMDLINE_POPT_OPT_LEGACY_S4,
};

/**
 * @brief Initialize the commandline interface for parsing options.
 *
 * This initialized the interface for parsing options given on the command
 * line. It sets up the loadparm and client credentials contexts.
 * The function will also setup fault handler, set logging to STDERR by
 * default, setup talloc logging and the panic handler.
 *
 * @param[in]  mem_ctx  The talloc memory context to use for allocating memory.
 *                      This should be a long living context till the client
 *                      exits.
 *
 * @param[in]  require_smbconf  Wether the smb.conf file should to be present
 *                              or not?
 *
 * @return true on success, false if an error occured.
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
 * @param[in]  opt  The options to retrieve.
 *
 * @return A pointer to the poptOption array.
 */
struct poptOption *samba_cmdline_get_popt(enum smb_cmdline_popt_options opt);

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
	.descrip    = "Deprecated legcacy options:", \
	.argDescrip = NULL },

/* TODO Get rid of me! */
#define POPT_LEGACY_S4 { \
	.longName   = NULL, \
	.shortName  = '\0', \
	.argInfo    = POPT_ARG_INCLUDE_TABLE, \
	.arg        = samba_cmdline_get_popt(SAMBA_CMDLINE_POPT_OPT_LEGACY_S4), \
	.val        = 0, \
	.descrip    = "Deprecated legcacy options:", \
	.argDescrip = NULL },

#endif /* _CMDLINE_H */
