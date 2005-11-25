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

struct smb2_session_setup {
	struct {
		/* static body buffer 16 (0x10) bytes */
		/* uint16_t buffer_code;  0x11 = 0x10 + 1 */
		uint16_t _pad;
		uint32_t unknown2; /* 0xF */
		uint32_t unknown3; /* 0x00 */
		/* uint16_t secblob_ofs */
		/* uint16_t secblob_size */

		/* dynamic body */
		DATA_BLOB secblob;
	} in;
	struct {
		/* static body buffer 8 (0x08) bytes */
		/* uint16_t buffer_code; 0x09 = 0x08 +1 */
		uint16_t _pad;
		/* uint16_t secblob_ofs */
		/* uint16_t secblob_size */

		/* dynamic body */
		DATA_BLOB secblob;

		/* extracted from the SMB2 header */
		uint64_t uid;
	} out;
};

struct smb2_tree_connect {
	struct {
		/* static body buffer 8 (0x08) bytes */
		/* uint16_t buffer_code; 0x09 = 0x08 + 1 */
		uint16_t unknown1; /* 0x0000 */
		/* uint16_t path_ofs */
		/* uint16_t path_size */

		/* dynamic body */
		const char *path; /* as non-terminated UTF-16 on the wire */
	} in;
	struct {
		/* static body buffer 16 (0x10) bytes */
		/* uint16_t buffer_code;  0x10 */
		uint16_t unknown1; /* 0x02 */
		uint32_t unknown2; /* 0x00 */
		uint32_t unknown3; /* 0x00 */
		uint32_t access_mask;

		/* extracted from the SMB2 header */
		uint32_t tid;
	} out;
};

#define SMB2_CREATE_FLAG_REQUEST_OPLOCK           0x0100
#define SMB2_CREATE_FLAG_REQUEST_EXCLUSIVE_OPLOCK 0x0800
#define SMB2_CREATE_FLAG_GRANT_OPLOCK             0x0001
#define SMB2_CREATE_FLAG_GRANT_EXCLUSIVE_OPLOCK   0x0080

struct smb2_create {
	struct {
		/* static body buffer 56 (0x38) bytes */
		/* uint16_t buffer_code;  0x39 = 0x38 + 1 */
		uint16_t oplock_flags; /* SMB2_CREATE_FLAG_* */
		uint32_t impersonation;
		uint32_t unknown3[4];
		uint32_t access_mask;

		uint32_t file_attr;
		uint32_t share_access;
		uint32_t open_disposition;
		uint32_t create_options;

		/* uint16_t fname_ofs */
		/* uint16_t fname_size */
		/* uint32_t blob_ofs; */
		/* uint32_t blob_size; */

		/* dynamic body */
		const char *fname;

		/* optional list of extended attributes */
		struct smb_ea_list eas;
	} in;

	struct {
		/* static body buffer 88 (0x58) bytes */
		/* uint16_t buffer_code;  0x59 = 0x58 + 1 */
		uint16_t oplock_flags; /* SMB2_CREATE_FLAG_* */
		uint32_t create_action;
		NTTIME   create_time;
		NTTIME   access_time;
		NTTIME   write_time;
		NTTIME   change_time;
		uint64_t alloc_size;
		uint64_t size;
		uint32_t file_attr;
		uint32_t _pad;
		struct smb2_handle handle;
		/* uint32_t blob_ofs; */
		/* uint32_t blob_size; */

		/* dynamic body */
		DATA_BLOB blob;
	} out;
};


#define SMB2_CLOSE_FLAGS_FULL_INFORMATION (1<<0)

struct smb2_close {
	struct {
		/* static body buffer 24 (0x18) bytes */
		/* uint16_t buffer_code;  0x18 */
		uint16_t flags; /* SMB2_CLOSE_FLAGS_* */
		uint32_t _pad;
		struct smb2_handle handle;
	} in;

	struct {
		/* static body buffer 60 (0x3C) bytes */
		/* uint16_t buffer_code;  0x3C */
		uint16_t flags;
		uint32_t _pad;
		NTTIME   create_time;
		NTTIME   access_time;
		NTTIME   write_time;
		NTTIME   change_time;
		uint64_t alloc_size;
		uint64_t size;
		uint32_t file_attr;
	} out;
};

/* getinfo classes */
#define SMB2_GETINFO_FILE               0x01
#define SMB2_GETINFO_FS                 0x02
#define SMB2_GETINFO_SECURITY           0x03

/* flags for RAW_FILEINFO_SMB2_ALL_EAS */
#define SMB2_CONTINUE_FLAG_RESTART    0x01
#define SMB2_CONTINUE_FLAG_SINGLE     0x02

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
		struct smb2_handle handle;
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
		struct smb2_handle handle;
		DATA_BLOB blob;
	} in;
};

struct smb2_write {
	struct {
		/* static body buffer 48 (0x30) bytes */
		/* uint16_t buffer_code;  0x31 = 0x30 + 1 */
		/* uint16_t data_ofs; */
		/* uint32_t data_size; */
		uint64_t offset;
		struct smb2_handle handle;
		uint64_t unknown1; /* 0xFFFFFFFFFFFFFFFF */
		uint64_t unknown2; /* 0xFFFFFFFFFFFFFFFF */

		/* dynamic body */
		DATA_BLOB data;
	} in;

	struct {
		/* static body buffer 17 (0x11) bytes */
		/* uint16_t buffer_code;  0x11 */
		uint16_t _pad;
		uint32_t nwritten;
		uint64_t unknown1; /* 0x0000000000000000 */
		uint8_t _bug;
	} out;
};

struct smb2_read {
	struct {
		/* static body buffer 48 (0x30) bytes */
		/* uint16_t buffer_code;  0x31 = 0x30 + 1 */
		uint16_t _pad;
		uint32_t length;
		uint64_t offset;
		struct smb2_handle handle;
		uint64_t unknown1; /* 0x0000000000000000 */
		uint64_t unknown2; /* 0x0000000000000000 */
		uint8_t _bug;
	} in;

	struct {
		/* static body buffer 16 (0x10) bytes */
		/* uint16_t buffer_code;  0x11 = 0x10 + 1 */
		/* uint16_t data_ofs; */
		/* uint32_t data_size; */
		uint64_t unknown1; /* 0x0000000000000000 */

		/* dynamic body */
		DATA_BLOB data;
	} out;
};

/*
  SMB2 uses different level numbers for the same old SMB search levels
*/
#define SMB2_FIND_DIRECTORY_INFO         0x01
#define SMB2_FIND_FULL_DIRECTORY_INFO    0x02
#define SMB2_FIND_BOTH_DIRECTORY_INFO    0x03
#define SMB2_FIND_NAME_INFO              0x0C
#define SMB2_FIND_ID_BOTH_DIRECTORY_INFO 0x25
#define SMB2_FIND_ID_FULL_DIRECTORY_INFO 0x26

struct smb2_find {
	struct {
		/* static body buffer 32 (0x20) bytes */
		/* uint16_t buffer_code;  0x21 = 0x20 + 1 */
		uint8_t level;
		uint8_t continue_flags; /* SMB2_CONTINUE_FLAG_* */
		uint32_t unknown; /* perhaps a continue token? */
		struct smb2_handle handle;
		/* uint16_t pattern_ofs; */
		/* uint32_t pattern_size; */
		uint32_t max_response_size;

		/* dynamic body */
		const char *pattern;
	} in;

	struct {
		/* static body buffer 8 (0x08) bytes */
		/* uint16_t buffer_code;  0x08 */
		/* uint16_t blob_ofs; */
		/* uint32_t blob_size; */

		/* dynamic body */
		DATA_BLOB blob;
	} out;
};

#define SMB2_TRANS_PIPE_FLAGS 0x0011c017 /* what are these? */

struct smb2_trans {
	struct {
		/* static body buffer 56 (0x38) bytes */
		/* uint16_t buffer_code;  0x39 = 0x38 + 1 */
		uint16_t _pad;
		uint32_t pipe_flags;
		struct smb2_handle handle;
		/* uint32_t out_ofs; */
		/* uint32_t out_size; */
		uint32_t unknown2;
		/* uint32_t in_ofs; */
		/* uint32_t in_size; */
		uint32_t max_response_size;
		uint64_t flags;

		/* dynamic body */
		DATA_BLOB out;
		DATA_BLOB in;
	} in;

	struct {
		/* static body buffer 48 (0x30) bytes */
		/* uint16_t buffer_code;  0x31 = 0x30 + 1 */
		uint16_t _pad;
		uint32_t pipe_flags;
		struct smb2_handle handle;
		/* uint32_t in_ofs; */
		/* uint32_t in_size; */
		/* uint32_t out_ofs; */
		/* uint32_t out_size; */
		uint32_t unknown2;
		uint32_t unknown3;

		/* dynamic body */
		DATA_BLOB in;
		DATA_BLOB out;
	} out;
};

struct smb2_flush {
	struct {
		uint32_t unknown;
		struct smb2_handle handle;
	} in;
};
