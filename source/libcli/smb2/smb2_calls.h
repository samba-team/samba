/* 
   Unix SMB/CIFS implementation.

   SMB2 client calls 

   Copyright (C) Andrew Tridgell 2005
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include "libcli/raw/interfaces.h"

struct smb2_negprot {
	struct {
		/* static body buffer 38 (0x26) bytes */
		/* uint16_t buffer_code;  0x24 (why?) */
		uint16_t unknown1;    /* 0x0001 */
		uint8_t  unknown2[32]; /* all zero */
		uint16_t unknown3; /* 0x00000 */
	} in;
	struct {
		/* static body buffer 64 (0x40) bytes */
		/* uint16_t buffer_code;  0x41 = 0x40 + 1 */
		uint16_t _pad;
		uint32_t unknown2; /* 0x06 */
		uint8_t  sessid[16];
		uint32_t unknown3; /* 0x0d */
		uint16_t unknown4; /* 0x00 */
		uint32_t unknown5; /* 0x01 */
		uint32_t unknown6; /* 0x01 */
		uint16_t unknown7; /* 0x01 */
		NTTIME   current_time;
		NTTIME   boot_time;
		/* uint16_t secblob_ofs */
		/* uint16_t secblob_size */
		uint32_t unknown9; /* 0x204d4c20 */

		/* dynamic body buffer */
		DATA_BLOB secblob;
	} out;
};

/* getinfo classes */
#define SMB2_GETINFO_FILE               0x01
#define SMB2_GETINFO_FS                 0x02
#define SMB2_GETINFO_SECURITY           0x03

/* NOTE! the getinfo fs and file levels exactly match up with the
   'passthru' SMB levels, which are levels >= 1000. The SMB2 client
   lib uses the names from the libcli/raw/ library */

struct smb2_getinfo {
	struct {
		/* static body buffer 40 (0x28) bytes */
		/* uint16_t buffer_code;  0x29 = 0x28 + 1 (why???) */
		uint16_t level;
		uint32_t max_response_size;
		uint32_t unknown1;
		uint32_t unknown2;
		uint32_t flags; /* level specific */
		uint32_t flags2; /* used by all_eas level */
		union smb_handle file;
	} in;

	struct {
		/* static body buffer 8 (0x08) bytes */
		/* uint16_t buffer_code; 0x09 = 0x08 + 1 */
		/* uint16_t blob_ofs; */
		/* uint16_t blob_size; */

		/* dynamic body */
		DATA_BLOB blob;
	} out;
};

struct smb2_setinfo {
	struct {
		uint16_t level;
		uint32_t flags;
		union smb_handle file;
		DATA_BLOB blob;
	} in;
};

struct cli_credentials;
struct event_context;
#include "libcli/smb2/smb2_proto.h"
