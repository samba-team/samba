/*
   Unix SMB/CIFS implementation.
   client file operations
   Copyright (C) Andrew Tridgell 1994-1998
   Copyright (C) Jeremy Allison 2001-2002
   Copyright (C) James Myers 2003

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

#include "replace.h"
#include "system/filesys.h"
#include "smb_constants.h"
#include <talloc.h>
#include "libcli/util/ntstatus.h"

#ifndef _SMB_UTIL_H
#define _SMB_UTIL_H

const char *smb_protocol_types_string(enum protocol_types protocol);
char *attrib_string(TALLOC_CTX *mem_ctx, uint32_t attrib);
uint32_t unix_perms_to_wire(mode_t perms);
mode_t wire_perms_to_unix(uint32_t perms);
mode_t wire_filetype_to_unix(uint32_t wire_type);
uint32_t unix_filetype_to_wire(mode_t mode);
mode_t wire_mode_to_unix(uint32_t wire);
uint32_t unix_mode_to_wire(mode_t mode);

bool smb_buffer_oob(uint32_t bufsize, uint32_t offset, uint32_t length);

uint8_t *smb_bytes_push_str(uint8_t *buf, bool ucs2,
			    const char *str, size_t str_len,
			    size_t *pconverted_size);
uint8_t *smb_bytes_push_bytes(uint8_t *buf, uint8_t prefix,
			      const uint8_t *bytes, size_t num_bytes);
uint8_t *trans2_bytes_push_str(uint8_t *buf, bool ucs2,
			       const char *str, size_t str_len,
			       size_t *pconverted_size);
uint8_t *trans2_bytes_push_bytes(uint8_t *buf,
				 const uint8_t *bytes, size_t num_bytes);
NTSTATUS smb_bytes_pull_str(TALLOC_CTX *mem_ctx, char **_str, bool ucs2,
			    const uint8_t *buf, size_t buf_len,
			    const uint8_t *position,
			    size_t *_consumed);

enum smb_signing_setting smb_signing_setting_translate(const char *str);
enum smb_encryption_setting smb_encryption_setting_translate(const char *str);

enum smb_transport_type {
	SMB_TRANSPORT_TYPE_UNKNOWN = 0,
	SMB_TRANSPORT_TYPE_NBT,
	SMB_TRANSPORT_TYPE_TCP,
};

struct smb_transport {
	enum smb_transport_type type;
	uint16_t port;
};

struct smb_transports {
#define SMB_TRANSPORTS_MAX_TRANSPORTS 10
	uint8_t num_transports;
	struct smb_transport transports[SMB_TRANSPORTS_MAX_TRANSPORTS];
};

struct smb_transports smb_transports_parse(const char *param_name,
					   const char * const *transports);

#endif /* _SMB_UTIL_H */
