/* 
   Unix SMB/CIFS implementation.
   SMB parameters and setup, plus a whole lot more.
   
   Copyright (C) Andrew Tridgell              1992-2000
   Copyright (C) John H Terpstra              1996-2002
   Copyright (C) Luke Kenneth Casson Leighton 1996-2000
   Copyright (C) Paul Ashton                  1998-2000
   Copyright (C) Simo Sorce                   2001-2002
   Copyright (C) Martin Pool		      2002
   
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

#ifndef _REWRITE_H
#define _REWRITE_H

#define Undefined (-1)
#define False (0)
#define True (1)
#define Auto (2)
#define Required (3)

/* string manipulation flags - see clistr.c and srvstr.c */
#define STR_TERMINATE 1
#define STR_UPPER 2
#define STR_ASCII 4
#define STR_UNICODE 8
#define STR_NOALIGN 16
#define STR_NO_RANGE_CHECK 32
#define STR_LEN8BIT 64
#define STR_TERMINATE_ASCII 128 /* only terminate if ascii */
#define STR_LEN_NOTERM 256 /* the length field is the unterminated length */

/* Debugging stuff */
#include "debug.h"

/* types of socket errors */
enum socket_error {SOCKET_READ_TIMEOUT,
		   SOCKET_READ_EOF,
		   SOCKET_READ_ERROR,
		   SOCKET_WRITE_ERROR,
		   SOCKET_READ_BAD_SIG};

#include "doserr.h"

/* ucs2 string types. */
typedef smb_ucs2_t wpstring[PSTRING_LEN];
typedef smb_ucs2_t wfstring[FSTRING_LEN];

#ifdef WORDS_BIGENDIAN
#define UCS2_SHIFT 8
#else
#define UCS2_SHIFT 0
#endif

/* turn a 7 bit character into a ucs2 character */
#define UCS2_CHAR(c) ((c) << UCS2_SHIFT)

/* for compatibility */
#define SID_NAME_USE samr_SidType

#include "enums.h"
#include "events.h"
#include "librpc/gen_ndr/ndr_misc.h"
#include "smb_interfaces.h"
#include "librpc/ndr/libndr.h"

/* used for network interfaces */
struct interface
{
	struct interface *next, *prev;
	struct in_addr ip;
	struct in_addr bcast;
	struct in_addr nmask;
};

/* key and data in the connections database - used in smbstatus and smbd */
struct connections_key {
	pid_t pid;
	int cnum;
	fstring name;
};

struct connections_data {
	int magic;
	pid_t pid;
	int cnum;
	uid_t uid;
	gid_t gid;
	char name[24];
	char addr[24];
	char machine[FSTRING_LEN];
	time_t start;
	uint32_t bcast_msg_flags;
};

/* the following are used by loadparm for option lists */
typedef enum
{
  P_BOOL,P_BOOLREV,P_CHAR,P_INTEGER,P_OCTAL,P_LIST,
  P_STRING,P_USTRING,P_ENUM,P_SEP
} parm_type;

typedef enum
{
  P_LOCAL,P_GLOBAL,P_SEPARATOR,P_NONE
} parm_class;

struct enum_list {
	int value;
	const char *name;
};

struct parm_struct
{
	const char *label;
	parm_type type;
	parm_class class;
	void *ptr;
	BOOL (*special)(int snum, const char *, char **);
	const struct enum_list *enum_list;
	uint_t flags;
	union {
		BOOL bvalue;
		int ivalue;
		char *svalue;
		char cvalue;
		char **lvalue;
	} def;
};

struct bitmap {
	uint32_t *b;
	uint_t n;
};

#define FLAG_BASIC 	0x0001 /* fundamental options */
#define FLAG_SHARE 	0x0002 /* file sharing options */
#define FLAG_PRINT 	0x0004 /* printing options */
#define FLAG_GLOBAL 	0x0008 /* local options that should be globally settable in SWAT */
#define FLAG_WIZARD 	0x0010 /* Parameters that the wizard will operate on */
#define FLAG_ADVANCED 	0x0020 /* Parameters that the wizard will operate on */
#define FLAG_DEVELOPER 	0x0040 /* Parameters that the wizard will operate on */
#define FLAG_DEPRECATED 0x1000 /* options that should no longer be used */
#define FLAG_HIDE  	0x2000 /* options that should be hidden in SWAT */
#define FLAG_DOS_STRING 0x4000 /* convert from UNIX to DOS codepage when reading this string. */
#define FLAG_CMDLINE    0x8000 /* this option was set from the command line */

#ifndef LOCKING_VERSION
#define LOCKING_VERSION 4
#endif /* LOCKING_VERSION */

#ifndef SIGNAL_CAST
#define SIGNAL_CAST (RETSIGTYPE (*)(int))
#endif

#ifndef SELECT_CAST
#define SELECT_CAST
#endif

/*
 * Loopback command offsets.
 */

#define OPBRK_CMD_LEN_OFFSET 0
#define OPBRK_CMD_PORT_OFFSET 4
#define OPBRK_CMD_HEADER_LEN 6

#define OPBRK_MESSAGE_CMD_OFFSET 0

/* Message types */
#define OPLOCK_BREAK_CMD 0x1
#define KERNEL_OPLOCK_BREAK_CMD 0x2
#define LEVEL_II_OPLOCK_BREAK_CMD 0x3
#define ASYNC_LEVEL_II_OPLOCK_BREAK_CMD 0x4

/*
 * Capabilities abstracted for different systems.
 */

#define KERNEL_OPLOCK_CAPABILITY 0x1

/*
 * Oplock break command code sent via the kernel interface (if it exists).
 *
 * Form of this is :
 *
 *  0     2       2+devsize 2+devsize+inodesize
 *  +----+--------+--------+----------+
 *  | cmd| dev    |  inode |  fileid  |
 *  +----+--------+--------+----------+
 */
#define KERNEL_OPLOCK_BREAK_DEV_OFFSET 2
#define KERNEL_OPLOCK_BREAK_INODE_OFFSET (KERNEL_OPLOCK_BREAK_DEV_OFFSET + sizeof(SMB_DEV_T))
#define KERNEL_OPLOCK_BREAK_FILEID_OFFSET (KERNEL_OPLOCK_BREAK_INODE_OFFSET + sizeof(SMB_INO_T))
#define KERNEL_OPLOCK_BREAK_MSG_LEN (KERNEL_OPLOCK_BREAK_FILEID_OFFSET + sizeof(unsigned long))


#define CMD_REPLY 0x8000

#include "smb_macros.h"

/* A netbios name structure. */
struct nmb_name {
	nstring      name;
	char         scope[64];
	uint_t name_type;
};


/* A netbios node status array element. */
struct node_status {
	nstring name;
	uint8_t type;
	uint8_t flags;
};

#include "rpc_secdes.h"

typedef struct user_struct
{
	struct user_struct *next, *prev;
	uint16 vuid; /* Tag for this entry. */
	uid_t uid; /* uid of a validated user */
	gid_t gid; /* gid of a validated user */

	userdom_struct user;
	char *homedir;
	char *unix_homedir;
	char *logon_script;
	
	BOOL guest;

	/* following groups stuff added by ih */
	/* This groups info is needed for when we become_user() for this uid */
	int n_groups;
	gid_t *groups;

	NT_USER_TOKEN *nt_user_token;
	PRIVILEGE_SET *privs;

	DATA_BLOB session_key;

	char *session_keystr; /* used by utmp and pam session code.  
				 TDB key string */
	int homes_snum;

	struct auth_serversupplied_info *server_info;

} user_struct;

#include "client.h"

/*
   Do you want session setups at user level security with a invalid
   password to be rejected or allowed in as guest? WinNT rejects them
   but it can be a pain as it means "net view" needs to use a password

   You have 3 choices in the setting of map_to_guest:

   "NEVER_MAP_TO_GUEST" means session setups with an invalid password
   are rejected. This is the default.

   "MAP_TO_GUEST_ON_BAD_USER" means session setups with an invalid password
   are rejected, unless the username does not exist, in which case it
   is treated as a guest login

   "MAP_TO_GUEST_ON_BAD_PASSWORD" means session setups with an invalid password
   are treated as a guest login

   Note that map_to_guest only has an effect in user or server
   level security.
*/

#define NEVER_MAP_TO_GUEST 0
#define MAP_TO_GUEST_ON_BAD_USER 1
#define MAP_TO_GUEST_ON_BAD_PASSWORD 2

#define SAFE_NETBIOS_CHARS ". -_"

/* generic iconv conversion structure */
typedef struct {
	size_t (*direct)(void *cd, const char **inbuf, size_t *inbytesleft,
			 char **outbuf, size_t *outbytesleft);
	size_t (*pull)(void *cd, const char **inbuf, size_t *inbytesleft,
		       char **outbuf, size_t *outbytesleft);
	size_t (*push)(void *cd, const char **inbuf, size_t *inbytesleft,
		       char **outbuf, size_t *outbytesleft);
	void *cd_direct, *cd_pull, *cd_push;
	char *from_name, *to_name;
} *smb_iconv_t;

#define SAFE_STRING_FUNCTION_NAME FUNCTION_MACRO
#define SAFE_STRING_LINE __LINE__

#define srvstr_push(base_ptr, dest, src, dest_len, flags) srvstr_push_fn(SAFE_STRING_FUNCTION_NAME, SAFE_STRING_LINE, base_ptr, dest, src, dest_len, flags)

/* Stuff from 3_0 trans2.h */

#define l1_fdateCreation 0
#define l1_fdateLastAccess 4
#define l1_fdateLastWrite 8
#define l1_cbFile 12
#define l1_cbFileAlloc 16
#define l1_attrFile 20
#define l1_cchName 22
#define l1_achName 23

#define l2_fdateCreation 0
#define l2_fdateLastAccess 4
#define l2_fdateLastWrite 8
#define l2_cbFile 12
#define l2_cbFileAlloc 16
#define l2_attrFile 20
#define l2_cbList 22
#define l2_cchName 26
#define l2_achName 27

#define l260_achName 94

#define l1_idFileSystem 0
#define l1_cSectorUnit 4
#define l1_cUnit 8
#define l1_cUnitAvail 12
#define l1_cbSector 16

#define l2_vol_fdateCreation 0
#define l2_vol_cch 4
#define l2_vol_szVolLabel 5

#define DIRLEN_GUESS (45+MAX(l1_achName,l2_achName))

#define SMB_QUERY_FS_LABEL_INFO         0x101
#define SMB_FS_LABEL_INFORMATION                        1002

#define SMB_INFO_QUERY_EAS_FROM_LIST    3  /* only valid on query not set */
#define SMB_INFO_QUERY_ALL_EAS          4  /* only valid on query not set */

#define SMB_FILE_DISPOSITION_INFORMATION                1013
#define SMB_FILE_ALLOCATION_INFORMATION                 1019
#define SMB_FILE_END_OF_FILE_INFORMATION                1020

#define SMB_QUERY_FILE_ALLOCATION_INFO  0x105
#define SMB_QUERY_FILE_END_OF_FILEINFO  0x106

#define SMB_QUERY_FILE_UNIX_LINK       0x201

#include "popt_common.h"

#endif /* _REWRITE_H */
