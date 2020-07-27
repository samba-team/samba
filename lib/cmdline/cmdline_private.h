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

#ifndef _CMDLINE_PRIVATE_H
#define _CMDLINE_PRIVATE_H

#include "lib/cmdline/cmdline.h"

/**
 * @internal
 *
 * @brief Initialize the commandline interface for parsing options.
 *
 * This the common function to initialize the command line interface. This
 * initializes:
 *
 *   - Crash setup
 *   - logging system sening logs to stdout
 *   - talloc leak reporting
 *
 * @param[in]  mem_ctx  The talloc memory context to use for allocating memory.
 *                      This should be a long living context till the client
 *                      exits.
 *
 * @return true on success, false if an error occured.
 */
bool samba_cmdline_init_common(TALLOC_CTX *mem_ctx);

/**
 * @internal
 *
 * @brief Set the talloc context for the command line interface.
 *
 * This is stored as a static pointer.
 *
 * @param[in]  mem_ctx  The talloc memory context.
 *
 * @return true on success, false if an error occured.
 */
bool samba_cmdline_set_talloc_ctx(TALLOC_CTX *mem_ctx);

/**
 * @internal
 *
 * @brief Get the talloc context for the cmdline interface.
 *
 * @return A talloc context.
 */
TALLOC_CTX *samba_cmdline_get_talloc_ctx(void);

/**
 * @internal
 *
 * @brief Set the loadparm context for the command line interface.
 *
 * @param[in]  lp_ctx  The loadparm context to use.
 *
 * @return true on success, false if an error occured.
 */
bool samba_cmdline_set_lp_ctx(struct loadparm_context *lp_ctx);

/**
 * @internal
 *
 * @brief Set the client credentials for the commandline interface.
 *
 * @param[in]  creds   The client credentials to use.
 *
 * @return true on success, false if an error occured.
 */
bool samba_cmdline_set_creds(struct cli_credentials *creds);

#endif /* _CMDLINE_PRIVATE_H */
