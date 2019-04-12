/* 
   Unix SMB/CIFS implementation.
   Utility functions for Samba
   Copyright (C) Andrew Tridgell 1992-1999
   Copyright (C) Jelmer Vernooij 2005
   Copyright (C) Swen Schillig 2019
    
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

#ifndef __UTIL_SAMBA_UTIL_H__
#define __UTIL_SAMBA_UTIL_H__

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

/**
 * Write dump of binary data to a callback
 */
void dump_data_cb(const uint8_t *buf, int len,
		  bool omit_zero_bytes,
		  void (*cb)(const char *buf, void *private_data),
		  void *private_data);

/**
 * Write dump of binary data to a FILE
 */
void dump_data_file(const uint8_t *buf, int len, bool omit_zero_bytes,
		    FILE *f);

/**
 * Write dump of binary data to the log file.
 *
 * The data is only written if the log level is at least level.
 */
_PUBLIC_ void dump_data(int level, const uint8_t *buf,int len);

/**
 * Write dump of binary data to the log file.
 *
 * The data is only written if the log level is at least level for
 * debug class dbgc_class.
 */
_PUBLIC_ void dump_data_dbgc(int dbgc_class, int level, const uint8_t *buf, int len);

#endif
