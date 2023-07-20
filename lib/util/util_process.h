/*
 *  Unix SMB/CIFS implementation.
 *
 *  Process utils.
 *
 *  Copyright (c) 2013      Andreas Schneider <asn@samba.org>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _SAMBA_UTIL_PROCESS_H
#define _SAMBA_UTIL_PROCESS_H

#include "replace.h"

/**
 * @brief Set the process comment name.
 *
 * @param[in]  comment  The comment to set which shouldn't be longer than 16
 *                      16 characters (including \0).
 *
 * @return              -1 on error, 0 on success.
 */
int prctl_set_comment(const char *comment_format, ...) PRINTF_ATTRIBUTE(1,2);

/**
 * @brief Set the process comment name and longname
 *
 * @param[in]  short_format    The comment to set which shouldn't be longer than 16
 *                             16 characters (including \0).
 * @param[in]  long_format     The format string and arguments to produce the long
 *                             form of the process name.
 *
 * @return              -1 on error, 0 on success.
 */
void process_set_title(const char *short_format, const char *long_format, ...)
	PRINTF_ATTRIBUTE(1,3) PRINTF_ATTRIBUTE(2,3);

/**
 * @brief Get the process comment name set from process_set_title()
 *
 * @return              process comment name
 */
const char *process_get_short_title(void);

/**
 * @brief Get the process longname set from process_set_title()
 *
 * @return              process longname
 */
const char *process_get_long_title(void);

/*
 * @brief Save the binary name for later printing in smb_panic()
 *
 * @param[in]  progname        The binary name at process startup
 *
 * This is just for debugging in a panic, so we don't want to do
 * anything more than return a fixed pointer, so we save a copy to a
 * static variable.
 */
void process_save_binary_name(const char *progname);

/**
 * @brief Get the binary name set at startup process_save_binary_name()
 *
 * @return              binary name set at startup
 */
/* Samba binaries will set this during popt handling */
const char *process_get_saved_binary_name(void);


#endif
