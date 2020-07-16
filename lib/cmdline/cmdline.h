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

/**
 * @brief Initialize the commandline interface for parsing options.
 *
 * This initialized the interface for parsing options given on the command
 * line. It sets up the loadparm and client credentials contexts.
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
bool samba_cmdline_init(TALLOC_CTX *mem_ctx, bool require_smbconf);

/**
 * @brief Get a pointer of loadparm context used for the command line interface.
 *
 * @return The loadparm context.
 */
struct loadparm_context *samba_cmdline_get_lp_ctx(void);

#endif /* _CMDLINE_H */
