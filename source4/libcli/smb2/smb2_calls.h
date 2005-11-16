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

/*
  file handles in SMB2 are 16 bytes
*/
struct smb2_handle {
	uint64_t data[2];
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
		uint32_t unknown2;
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

		DATA_BLOB blob;
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

/* fs information levels */
#define SMB2_GETINFO_FS_01              0x0102
#define SMB2_GETINFO_FS_03              0x0302
#define SMB2_GETINFO_FS_04              0x0402
#define SMB2_GETINFO_FS_ATTRIB_INFO     0x0502
#define SMB2_GETINFO_FS_06              0x0602
#define SMB2_GETINFO_FS_07              0x0702
#define SMB2_GETINFO_FS_08              0x0802

/* class 3 levels */
#define SMB2_GETINFO_SECURITY           0x0003

/* file information levels */
#define SMB2_GETINFO_FILE_BASIC_INFO    0x0401
#define SMB2_GETINFO_FILE_SIZE_INFO     0x0501
#define SMB2_GETINFO_FILE_ID            0x0601
#define SMB2_GETINFO_FILE_EA_SIZE       0x0701
#define SMB2_GETINFO_FILE_ACCESS_INFO   0x0801
#define SMB2_GETINFO_FILE_0E            0x0e01
#define SMB2_GETINFO_FILE_ALL_EAS       0x0f01
#define SMB2_GETINFO_FILE_10            0x1001
#define SMB2_GETINFO_FILE_11            0x1101
#define SMB2_GETINFO_FILE_ALL_INFO      0x1201
#define SMB2_GETINFO_FILE_SHORT_INFO    0x1501
#define SMB2_GETINFO_FILE_STREAM_INFO   0x1601
#define SMB2_GETINFO_FILE_EOF_INFO      0x1c01
#define SMB2_GETINFO_FILE_STANDARD_INFO 0x2201
#define SMB2_GETINFO_FILE_ATTRIB_INFO   0x2301


struct smb2_getinfo {
	struct {
		/* static body buffer 40 (0x28) bytes */
		/* uint16_t buffer_code;  0x29 = 0x28 + 1 (why???) */
		uint16_t level;
		uint32_t max_response_size;
		uint32_t unknown1;
		uint32_t flags; /* level specific */
		uint32_t unknown3;
		uint32_t unknown4;
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

union smb2_fileinfo {
	struct {
		NTTIME   create_time;
		NTTIME   access_time;
		NTTIME   write_time;
		NTTIME   change_time;
		uint32_t file_attr;
		uint32_t unknown;
	} basic_info;

	struct {
		uint64_t alloc_size;
		uint64_t size;
		uint32_t nlink;
		uint8_t  delete_pending;
		uint8_t  directory;
	} size_info;

	struct {
		uint64_t file_id;
	} file_id;

	struct {
		uint32_t ea_size;
	} ea_size;

	struct {
		uint32_t access_mask;
	} access_info;

	struct {
		uint32_t unknown1;
		uint32_t unknown2;
	} unknown0e;

	struct smb_ea_list all_eas;

	struct {
		uint32_t unknown;
	} unknown10;

	struct {
		uint32_t unknown;
	} unknown11;

	struct {
		NTTIME   create_time;
		NTTIME   access_time;
		NTTIME   write_time;
		NTTIME   change_time;
		uint32_t file_attr;
		/* uint32_t _pad; */
		uint64_t alloc_size;
		uint64_t size;
		uint32_t nlink;
		uint8_t  delete_pending;
		uint8_t  directory;
		/* uint16_t _pad; */
		uint64_t file_id;
		uint32_t ea_size;
		uint32_t access_mask;
		uint64_t unknown5;
		uint64_t unknown6;
		const char *fname;
	} all_info;

	struct {
		const char *short_name;
	} short_info;

	struct stream_information stream_info;

	struct {
		uint64_t size;
		uint64_t unknown;
	} eof_info;

	struct {
		NTTIME   create_time;
		NTTIME   access_time;
		NTTIME   write_time;
		NTTIME   change_time;
		uint64_t alloc_size;
		uint64_t size;
		uint32_t file_attr;
		uint32_t unknown;
	} standard_info;

	struct {
		uint32_t file_attr;
		uint32_t unknown;
	} attrib_info;

	struct {
		struct security_descriptor *sd;
	} security;
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
