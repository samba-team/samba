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

/**
 * @brief Set the process comment name.
 *
 * @param[in]  comment  The comment to set which shouldn't be longer than 16
 *                      16 characters (including \0).
 *
 * @return              -1 on error, 0 on success.
 */
int prctl_set_comment(const char *comment);

#endif
