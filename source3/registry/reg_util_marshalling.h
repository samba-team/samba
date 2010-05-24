/*
 * Unix SMB/CIFS implementation.
 * Registry helper routines
 * Copyright (C) Volker Lendecke 2006
 * 
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option)
 * any later version.
 * 
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 * 
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _REG_UTIL_MARSHALLING_H
#define _REG_UTIL_MARSHALLING_H

WERROR registry_pull_value(TALLOC_CTX *mem_ctx,
			   struct registry_value **pvalue,
			   enum winreg_Type type, uint8 *data,
			   uint32 size, uint32 length);

WERROR registry_push_value(TALLOC_CTX *mem_ctx,
			   const struct registry_value *value,
			   DATA_BLOB *presult);

#endif /* _REG_UTIL_MARSHALLING_H */
