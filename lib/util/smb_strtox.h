/*
 * Unix SMB/CIFS implementation.
 *
 * Copyright (C) Swen Schillig 2019
 *
 *   ** NOTE! The following LGPL license applies to this file.
 *   ** This does NOT imply that all of Samba is released
 *   ** under the LGPL
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */

#ifndef SMB_STRTOX_H
#define SMB_STRTOX_H

#define SMB_STR_STANDARD  0x00
#define SMB_STR_ALLOW_NEGATIVE 0x01
#define SMB_STR_FULL_STR_CONV  0x02
#define SMB_STR_ALLOW_NO_CONVERSION 0x04
#define SMB_STR_GLIBC_STANDARD (SMB_STR_ALLOW_NO_CONVERSION | \
				SMB_STR_ALLOW_NEGATIVE)

unsigned long int
smb_strtoul(const char *nptr, char **endptr, int base, int *err, int flags);

unsigned long long int
smb_strtoull(const char *nptr, char **endptr, int base, int *err, int flags);

#endif
