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
		uint32_t unknown1;    /* 0x00010024 */
		uint16_t unknown2;    /* 0x00 */
		uint8_t  unknown3[32]; /* all zero */
	} in;
	struct {
		uint16_t buffer_code;
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
		uint16_t unknown8; /* 0x80 */
		/* uint16_t secblob size here */
		uint32_t unknown9; /* 0x204d4c20 */
		DATA_BLOB secblob;
	} out;
};

struct smb2_session_setup {
	struct {
		uint32_t unknown1; /* 0x11 */
		uint32_t unknown2; /* 0xF */
		uint32_t unknown3; /* 0x00 */
		/* uint16_t secblob ofs/size here */
		DATA_BLOB secblob;
	} in;
	struct {
		uint16_t buffer_code;
		uint16_t _pad;
		/* uint16_t secblob ofs/size here */
		DATA_BLOB secblob;
		uint64_t uid; /* returned in header */
	} out;
};

struct smb2_tree_connect {
	struct {
		uint32_t unknown1; /* 0x09 */
		const char *path;
	} in;
	struct {
		uint16_t buffer_code;
		uint16_t unknown1; /* 0x02 */
		uint32_t unknown2; /* 0x00 */
		uint32_t unknown3; /* 0x00 */
		uint32_t access_mask;
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
		uint16_t buffer_code; /* 0x39 */
		uint16_t oplock_flags; /* SMB2_CREATE_FLAG_* */
		uint32_t unknown2;
		uint32_t unknown3[4];
		uint32_t access_mask;
		uint32_t file_attr;
		uint32_t share_access;
		uint32_t open_disposition;
		uint32_t create_options;
		/* ofs/len of name here, 16 bits */
		uint32_t unknown6;
		const char *fname;
		uint32_t unknown7;
		uint32_t unknown8;
		uint32_t unknown9;
		uint32_t unknown10;
		uint64_t unknown11;
	} in;

	struct {
		uint16_t buffer_code; /* 0x59 */
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
		uint32_t unknown4;
		uint32_t unknown5;
	} out;
};


#define SMB2_CLOSE_FLAGS_FULL_INFORMATION (1<<0)

struct smb2_close {
	struct {
		uint16_t buffer_code;
		uint16_t flags; /* SMB2_CLOSE_FLAGS_* */
		uint32_t _pad;
		struct smb2_handle handle;
	} in;

	struct {
		uint16_t buffer_code;
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

