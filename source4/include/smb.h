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

#ifndef _SMB_H
#define _SMB_H

#define NMB_PORT 137
#define DGRAM_PORT 138
#define SMB_PORT1 445
#define SMB_PORT2 139
#define SMB_PORTS "445 139"

#define False (0)
#define True (1)
#define Auto (2)

enum smb_signing_state {SMB_SIGNING_OFF, SMB_SIGNING_SUPPORTED, SMB_SIGNING_REQUIRED};

#ifndef _BOOL
typedef int BOOL;
#define _BOOL       /* So we don't typedef BOOL again in vfs.h */
#endif

#define SIZEOFWORD 2

#ifndef DEF_CREATE_MASK
#define DEF_CREATE_MASK (0755)
#endif

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

/* deny modes */
#define DENY_DOS 0
#define DENY_ALL 1
#define DENY_WRITE 2
#define DENY_READ 3
#define DENY_NONE 4
#define DENY_FCB 7

/* open modes */
#define DOS_OPEN_RDONLY 0
#define DOS_OPEN_WRONLY 1
#define DOS_OPEN_RDWR 2
#define DOS_OPEN_FCB 0xF


/**********************************/
/* SMBopen field definitions      */
#define OPEN_FLAGS_DENY_MASK  0x70
#define OPEN_FLAGS_DENY_DOS   0x00
#define OPEN_FLAGS_DENY_ALL   0x10
#define OPEN_FLAGS_DENY_WRITE 0x20
#define OPEN_FLAGS_DENY_READ  0x30
#define OPEN_FLAGS_DENY_NONE  0x40

#define OPEN_FLAGS_MODE_MASK  0x0F
#define OPEN_FLAGS_OPEN_READ     0
#define OPEN_FLAGS_OPEN_WRITE    1
#define OPEN_FLAGS_OPEN_RDWR     2
#define OPEN_FLAGS_FCB        0xFF


/**********************************/
/* SMBopenX field definitions     */

/* OpenX Flags field. */
#define OPENX_FLAGS_ADDITIONAL_INFO      0x01
#define OPENX_FLAGS_REQUEST_OPLOCK       0x02
#define OPENX_FLAGS_REQUEST_BATCH_OPLOCK 0x04
#define OPENX_FLAGS_EA_LEN               0x08
#define OPENX_FLAGS_EXTENDED_RETURN      0x10

/* desired access (open_mode), split info 4 4-bit nibbles */
#define OPENX_MODE_ACCESS_MASK   0x000F
#define OPENX_MODE_ACCESS_READ   0x0000
#define OPENX_MODE_ACCESS_WRITE  0x0001
#define OPENX_MODE_ACCESS_RDWR   0x0002
#define OPENX_MODE_ACCESS_EXEC   0x0003
#define OPENX_MODE_ACCESS_FCB    0x000F

#define OPENX_MODE_DENY_SHIFT    4
#define OPENX_MODE_DENY_MASK     (0xF        << OPENX_MODE_DENY_SHIFT)
#define OPENX_MODE_DENY_DOS      (DENY_DOS   << OPENX_MODE_DENY_SHIFT)
#define OPENX_MODE_DENY_ALL      (DENY_ALL   << OPENX_MODE_DENY_SHIFT)
#define OPENX_MODE_DENY_WRITE    (DENY_WRITE << OPENX_MODE_DENY_SHIFT)
#define OPENX_MODE_DENY_READ     (DENY_READ  << OPENX_MODE_DENY_SHIFT)
#define OPENX_MODE_DENY_NONE     (DENY_NONE  << OPENX_MODE_DENY_SHIFT)
#define OPENX_MODE_DENY_FCB      (0xF        << OPENX_MODE_DENY_SHIFT)

#define OPENX_MODE_LOCALITY_MASK 0x0F00 /* what does this do? */

#define OPENX_MODE_NO_CACHE      0x1000
#define OPENX_MODE_WRITE_THRU    0x4000

/* open function values */
#define OPENX_OPEN_FUNC_MASK  0x3
#define OPENX_OPEN_FUNC_FAIL  0x0
#define OPENX_OPEN_FUNC_OPEN  0x1
#define OPENX_OPEN_FUNC_TRUNC 0x2

/* The above can be OR'ed with... */
#define OPENX_OPEN_FUNC_CREATE 0x10

/* openx action in reply */
#define OPENX_ACTION_EXISTED    1
#define OPENX_ACTION_CREATED    2
#define OPENX_ACTION_TRUNCATED  3


/**********************************/
/* SMBntcreateX field definitions */

/* ntcreatex flags field. */
#define NTCREATEX_FLAGS_REQUEST_OPLOCK       0x02
#define NTCREATEX_FLAGS_REQUEST_BATCH_OPLOCK 0x04
#define NTCREATEX_FLAGS_OPEN_DIRECTORY       0x08
#define NTCREATEX_FLAGS_EXTENDED             0x10

/* the ntcreatex access_mask field 
   this is split into 4 pieces
   AAAABBBBCCCCCCCCDDDDDDDDDDDDDDDD
   A -> GENERIC_RIGHT_*
   B -> SEC_RIGHT_*
   C -> STD_RIGHT_*
   D -> SA_RIGHT_*
   
   which set of SA_RIGHT_* bits is applicable depends on the type
   of object.
*/



/* ntcreatex share_access field */
#define NTCREATEX_SHARE_ACCESS_NONE   0
#define NTCREATEX_SHARE_ACCESS_READ   1
#define NTCREATEX_SHARE_ACCESS_WRITE  2
#define NTCREATEX_SHARE_ACCESS_DELETE 4

/* ntcreatex open_disposition field */
#define NTCREATEX_DISP_SUPERSEDE 0     /* supersede existing file (if it exists) */
#define NTCREATEX_DISP_OPEN 1          /* if file exists open it, else fail */
#define NTCREATEX_DISP_CREATE 2        /* if file exists fail, else create it */
#define NTCREATEX_DISP_OPEN_IF 3       /* if file exists open it, else create it */
#define NTCREATEX_DISP_OVERWRITE 4     /* if exists overwrite, else fail */
#define NTCREATEX_DISP_OVERWRITE_IF 5  /* if exists overwrite, else create */

/* ntcreatex create_options field */
#define NTCREATEX_OPTIONS_DIRECTORY            0x0001
#define NTCREATEX_OPTIONS_WRITE_THROUGH        0x0002
#define NTCREATEX_OPTIONS_SEQUENTIAL_ONLY      0x0004
#define NTCREATEX_OPTIONS_SYNC_ALERT	       0x0010
#define NTCREATEX_OPTIONS_ASYNC_ALERT	       0x0020
#define NTCREATEX_OPTIONS_NON_DIRECTORY_FILE   0x0040
#define NTCREATEX_OPTIONS_NO_EA_KNOWLEDGE      0x0200
#define NTCREATEX_OPTIONS_EIGHT_DOT_THREE_ONLY 0x0400
#define NTCREATEX_OPTIONS_RANDOM_ACCESS        0x0800
#define NTCREATEX_OPTIONS_DELETE_ON_CLOSE      0x1000
#define NTCREATEX_OPTIONS_OPEN_BY_FILE_ID      0x2000

/* ntcreatex impersonation field */
#define NTCREATEX_IMPERSONATION_ANONYMOUS      0
#define NTCREATEX_IMPERSONATION_IDENTIFICATION 1
#define NTCREATEX_IMPERSONATION_IMPERSONATION  2
#define NTCREATEX_IMPERSONATION_DELEGATION     3

/* ntcreatex security flags bit field */
#define NTCREATEX_SECURITY_DYNAMIC             1
#define NTCREATEX_SECURITY_ALL                 2

/* ntcreatex create_action in reply */
#define NTCREATEX_ACTION_EXISTED     1
#define NTCREATEX_ACTION_CREATED     2
#define NTCREATEX_ACTION_TRUNCATED   3
/* the value 5 can also be returned when you try to create a directory with
   incorrect parameters - what does it mean? maybe created temporary file? */
#define NTCREATEX_ACTION_UNKNOWN 5

#include "doserr.h"

/*
 * SMB UCS2 (16-bit unicode) internal type.
 */

typedef uint16 smb_ucs2_t;

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

#define MAX_HOURS_LEN 32

/* for compatibility */
#define SID_NAME_USE samr_SidType

/*
 * The complete list of SIDS belonging to this user.
 * Created when a vuid is registered.
 * The definition of the user_sids array is as follows :
 *
 * token->user_sids[0] = primary user SID.
 * token->user_sids[1] = primary group SID.
 * token->user_sids[2..num_sids] = supplementary group SIDS.
 */

#define PRIMARY_USER_SID_INDEX 0
#define PRIMARY_GROUP_SID_INDEX 1

typedef struct nt_user_token {
	size_t num_sids;
	struct dom_sid **user_sids;
} NT_USER_TOKEN;

/* 32 bit time (sec) since 01jan1970 - cifs6.txt, section 3.5, page 30 */
typedef struct time_info
{
  uint32 time;
} UTIME;

/* used to hold an arbitrary blob of data */
typedef struct data_blob {
	uint8 *data;
	size_t length;
	void (*free)(struct data_blob *data_blob);
} DATA_BLOB;

#include "enums.h"
#include "events.h"
#include "librpc/gen_ndr/ndr_misc.h"
#include "smb_interfaces.h"
#include "librpc/ndr/libndr.h"

typedef struct userdom_struct {
	fstring smb_name; /* user name from the client */
	fstring unix_name; /* unix user name of a validated user */
	fstring full_name; /* to store full name (such as "Joe Bloggs") from gecos field of password file */
	fstring domain; /* domain that the client specified */
} userdom_struct;


/* used for server information: client, nameserv and ipc */
struct server_info_struct
{
  fstring name;
  uint32 type;
  fstring comment;
  fstring domain; /* used ONLY in ipc.c NOT namework.c */
  BOOL server_added; /* used ONLY in ipc.c NOT namework.c */
};


/* used for network interfaces */
struct interface
{
	struct interface *next, *prev;
	struct in_addr ip;
	struct in_addr bcast;
	struct in_addr nmask;
};

#define NT_HASH_LEN 16
#define LM_HASH_LEN 16

/*
 * Flags for account policy.
 */
#define AP_MIN_PASSWORD_LEN 		1
#define AP_PASSWORD_HISTORY		2
#define AP_USER_MUST_LOGON_TO_CHG_PASS	3
#define AP_MAX_PASSWORD_AGE		4
#define AP_MIN_PASSWORD_AGE		5
#define AP_LOCK_ACCOUNT_DURATION	6
#define AP_RESET_COUNT_TIME		7
#define AP_BAD_ATTEMPT_LOCKOUT		8
#define AP_TIME_TO_LOGOUT		9


/*
 * Flags for local user manipulation.
 */

#define LOCAL_ADD_USER 0x1
#define LOCAL_DELETE_USER 0x2
#define LOCAL_DISABLE_USER 0x4
#define LOCAL_ENABLE_USER 0x8
#define LOCAL_TRUST_ACCOUNT 0x10
#define LOCAL_SET_NO_PASSWORD 0x20
#define LOCAL_SET_PASSWORD 0x40
#define LOCAL_SET_LDAP_ADMIN_PW 0x80
#define LOCAL_INTERDOM_ACCOUNT 0x100
#define LOCAL_AM_ROOT 0x200  /* Act as root */

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
	uint32 bcast_msg_flags;
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
	BOOL (*special)(const char *, char **);
	const struct enum_list *enum_list;
	unsigned flags;
	union {
		BOOL bvalue;
		int ivalue;
		char *svalue;
		char cvalue;
		char **lvalue;
	} def;
};

struct bitmap {
	uint32 *b;
	unsigned int n;
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


/* the basic packet size, assuming no words or bytes. Does not include the NBT header */
#define MIN_SMB_SIZE 35

/* when using NBT encapsulation every packet has a 4 byte header */
#define NBT_HDR_SIZE 4

/* offsets into message header for common items - NOTE: These have
   changed from being offsets from the base of the NBT packet to the base of the SMB packet.
   this has reduced all these values by 4
*/
#define HDR_COM 4
#define HDR_RCLS 5
#define HDR_REH 6
#define HDR_ERR 7
#define HDR_FLG 9
#define HDR_FLG2 10
#define HDR_PIDHIGH 12
#define HDR_SS_FIELD 14
#define HDR_TID 24
#define HDR_PID 26
#define HDR_UID 28
#define HDR_MID 30
#define HDR_WCT 32
#define HDR_VWV 33


/* types of buffers in core SMB protocol */
#define SMB_DATA_BLOCK 0x1
#define SMB_ASCII4     0x4


/* flag defines. CIFS spec 3.1.1 */
#define FLAG_SUPPORT_LOCKREAD       0x01
#define FLAG_CLIENT_BUF_AVAIL       0x02
#define FLAG_RESERVED               0x04
#define FLAG_CASELESS_PATHNAMES     0x08
#define FLAG_CANONICAL_PATHNAMES    0x10
#define FLAG_REQUEST_OPLOCK         0x20
#define FLAG_REQUEST_BATCH_OPLOCK   0x40
#define FLAG_REPLY                  0x80

/* the complete */
#define SMBmkdir      0x00   /* create directory */
#define SMBrmdir      0x01   /* delete directory */
#define SMBopen       0x02   /* open file */
#define SMBcreate     0x03   /* create file */
#define SMBclose      0x04   /* close file */
#define SMBflush      0x05   /* flush file */
#define SMBunlink     0x06   /* delete file */
#define SMBmv         0x07   /* rename file */
#define SMBgetatr     0x08   /* get file attributes */
#define SMBsetatr     0x09   /* set file attributes */
#define SMBread       0x0A   /* read from file */
#define SMBwrite      0x0B   /* write to file */
#define SMBlock       0x0C   /* lock byte range */
#define SMBunlock     0x0D   /* unlock byte range */
#define SMBctemp      0x0E   /* create temporary file */
#define SMBmknew      0x0F   /* make new file */
#define SMBchkpth     0x10   /* check directory path */
#define SMBexit       0x11   /* process exit */
#define SMBlseek      0x12   /* seek */
#define SMBtcon       0x70   /* tree connect */
#define SMBtconX      0x75   /* tree connect and X*/
#define SMBtdis       0x71   /* tree disconnect */
#define SMBnegprot    0x72   /* negotiate protocol */
#define SMBdskattr    0x80   /* get disk attributes */
#define SMBsearch     0x81   /* search directory */
#define SMBsplopen    0xC0   /* open print spool file */
#define SMBsplwr      0xC1   /* write to print spool file */
#define SMBsplclose   0xC2   /* close print spool file */
#define SMBsplretq    0xC3   /* return print queue */
#define SMBsends      0xD0   /* send single block message */
#define SMBsendb      0xD1   /* send broadcast message */
#define SMBfwdname    0xD2   /* forward user name */
#define SMBcancelf    0xD3   /* cancel forward */
#define SMBgetmac     0xD4   /* get machine name */
#define SMBsendstrt   0xD5   /* send start of multi-block message */
#define SMBsendend    0xD6   /* send end of multi-block message */
#define SMBsendtxt    0xD7   /* send text of multi-block message */

/* Core+ protocol */
#define SMBlockread	  0x13   /* Lock a range and read */
#define SMBwriteunlock 0x14 /* write then range then unlock it */
#define SMBreadbraw   0x1a  /* read a block of data with no smb header */
#define SMBwritebraw  0x1d  /* write a block of data with no smb header */
#define SMBwritec     0x20  /* secondary write request */
#define SMBwriteclose 0x2c  /* write a file then close it */

/* dos extended protocol */
#define SMBreadBraw      0x1A   /* read block raw */
#define SMBreadBmpx      0x1B   /* read block multiplexed */
#define SMBreadBs        0x1C   /* read block (secondary response) */
#define SMBwriteBraw     0x1D   /* write block raw */
#define SMBwriteBmpx     0x1E   /* write block multiplexed */
#define SMBwriteBs       0x1F   /* write block (secondary request) */
#define SMBwriteC        0x20   /* write complete response */
#define SMBsetattrE      0x22   /* set file attributes expanded */
#define SMBgetattrE      0x23   /* get file attributes expanded */
#define SMBlockingX      0x24   /* lock/unlock byte ranges and X */
#define SMBtrans         0x25   /* transaction - name, bytes in/out */
#define SMBtranss        0x26   /* transaction (secondary request/response) */
#define SMBioctl         0x27   /* IOCTL */
#define SMBioctls        0x28   /* IOCTL  (secondary request/response) */
#define SMBcopy          0x29   /* copy */
#define SMBmove          0x2A   /* move */
#define SMBecho          0x2B   /* echo */
#define SMBopenX         0x2D   /* open and X */
#define SMBreadX         0x2E   /* read and X */
#define SMBwriteX        0x2F   /* write and X */
#define SMBsesssetupX    0x73   /* Session Set Up & X (including User Logon) */
#define SMBffirst        0x82   /* find first */
#define SMBfunique       0x83   /* find unique */
#define SMBfclose        0x84   /* find close */
#define SMBkeepalive     0x85   /* keepalive */
#define SMBinvalid       0xFE   /* invalid command */

/* Extended 2.0 protocol */
#define SMBtrans2        0x32   /* TRANS2 protocol set */
#define SMBtranss2       0x33   /* TRANS2 protocol set, secondary command */
#define SMBfindclose     0x34   /* Terminate a TRANSACT2_FINDFIRST */
#define SMBfindnclose    0x35   /* Terminate a TRANSACT2_FINDNOTIFYFIRST */
#define SMBulogoffX      0x74   /* user logoff */

/* NT SMB extensions. */
#define SMBnttrans       0xA0   /* NT transact */
#define SMBnttranss      0xA1   /* NT transact secondary */
#define SMBntcreateX     0xA2   /* NT create and X */
#define SMBntcancel      0xA4   /* NT cancel */
#define SMBntrename      0xA5   /* NT rename */

/* used to indicate end of chain */
#define SMB_CHAIN_NONE   0xFF

/* These are the trans subcommands */
#define TRANSACT_SETNAMEDPIPEHANDLESTATE  0x01 
#define TRANSACT_DCERPCCMD                0x26
#define TRANSACT_WAITNAMEDPIPEHANDLESTATE 0x53

/* These are the NT transact sub commands. */
#define NT_TRANSACT_CREATE                1
#define NT_TRANSACT_IOCTL                 2
#define NT_TRANSACT_SET_SECURITY_DESC     3
#define NT_TRANSACT_NOTIFY_CHANGE         4
#define NT_TRANSACT_RENAME                5
#define NT_TRANSACT_QUERY_SECURITY_DESC   6

/* this is used on a TConX. I'm not sure the name is very helpful though */
#define SMB_SUPPORT_SEARCH_BITS        0x0001
#define SMB_SHARE_IN_DFS               0x0002

/* Named pipe write mode flags. Used in writeX calls. */
#define PIPE_RAW_MODE 0x4
#define PIPE_START_MESSAGE 0x8

/* the desired access to use when opening a pipe */
#define DESIRED_ACCESS_PIPE 0x2019f
 

/* Mapping of generic access rights for files to specific rights. */
#define FILE_GENERIC_ALL (STANDARD_RIGHTS_REQUIRED_ACCESS| NT_ACCESS_SYNCHRONIZE_ACCESS|FILE_ALL_ACCESS)

#define FILE_GENERIC_READ (STANDARD_RIGHTS_READ_ACCESS|FILE_READ_DATA|FILE_READ_ATTRIBUTES|\
							FILE_READ_EA|NT_ACCESS_SYNCHRONIZE_ACCESS)

#define FILE_GENERIC_WRITE (STANDARD_RIGHTS_WRITE_ACCESS|FILE_WRITE_DATA|FILE_WRITE_ATTRIBUTES|\
			    FILE_WRITE_EA|FILE_APPEND_DATA|NT_ACCESS_SYNCHRONIZE_ACCESS)

#define FILE_GENERIC_EXECUTE (STANDARD_RIGHTS_EXECUTE_ACCESS|FILE_READ_ATTRIBUTES|\
			    FILE_EXECUTE|NT_ACCESS_SYNCHRONIZE_ACCESS)


/* FileAttributes (search attributes) field */
#define FILE_ATTRIBUTE_READONLY		0x0001
#define FILE_ATTRIBUTE_HIDDEN		0x0002
#define FILE_ATTRIBUTE_SYSTEM		0x0004
#define FILE_ATTRIBUTE_VOLUME		0x0008
#define FILE_ATTRIBUTE_DIRECTORY	0x0010
#define FILE_ATTRIBUTE_ARCHIVE		0x0020
#define FILE_ATTRIBUTE_DEVICE		0x0040
#define FILE_ATTRIBUTE_NORMAL		0x0080
#define FILE_ATTRIBUTE_TEMPORARY	0x0100
#define FILE_ATTRIBUTE_SPARSE		0x0200
#define FILE_ATTRIBUTE_REPARSE_POINT	0x0400
#define FILE_ATTRIBUTE_COMPRESSED	0x0800
#define FILE_ATTRIBUTE_OFFLINE		0x1000
#define FILE_ATTRIBUTE_NONINDEXED	0x2000
#define FILE_ATTRIBUTE_ENCRYPTED	0x4000

/* Flags - combined with attributes. */
#define FILE_FLAG_WRITE_THROUGH    0x80000000L
#define FILE_FLAG_NO_BUFFERING     0x20000000L
#define FILE_FLAG_RANDOM_ACCESS    0x10000000L
#define FILE_FLAG_SEQUENTIAL_SCAN  0x08000000L
#define FILE_FLAG_DELETE_ON_CLOSE  0x04000000L
#define FILE_FLAG_BACKUP_SEMANTICS 0x02000000L
#define FILE_FLAG_POSIX_SEMANTICS  0x01000000L

/* Responses when opening a file. */
#define FILE_WAS_SUPERSEDED 0
#define FILE_WAS_OPENED 1
#define FILE_WAS_CREATED 2
#define FILE_WAS_OVERWRITTEN 3

/* File type flags */
#define FILE_TYPE_DISK  0
#define FILE_TYPE_BYTE_MODE_PIPE 1
#define FILE_TYPE_MESSAGE_MODE_PIPE 2
#define FILE_TYPE_PRINTER 3
#define FILE_TYPE_COMM_DEVICE 4
#define FILE_TYPE_UNKNOWN 0xFFFF

/* Flag for NT transact rename call. */
#define RENAME_REPLACE_IF_EXISTS 1

/* flags for SMBntrename call */
#define RENAME_FLAG_MOVE_CLUSTER_INFORMATION 0x102 /* ???? */
#define RENAME_FLAG_HARD_LINK                0x103
#define RENAME_FLAG_RENAME                   0x104
#define RENAME_FLAG_COPY                     0x105

/* Filesystem Attributes. */
#define FILE_CASE_SENSITIVE_SEARCH 0x01
#define FILE_CASE_PRESERVED_NAMES 0x02
#define FILE_UNICODE_ON_DISK 0x04
/* According to cifs9f, this is 4, not 8 */
/* Acconding to testing, this actually sets the security attribute! */
#define FILE_PERSISTENT_ACLS 0x08
/* These entries added from cifs9f --tsb */
#define FILE_FILE_COMPRESSION 0x10
#define FILE_VOLUME_QUOTAS 0x20
/* I think this is wrong. JRA #define FILE_DEVICE_IS_MOUNTED 0x20 */
#define FILE_VOLUME_SPARSE_FILE 0x40
#define FILE_VOLUME_IS_COMPRESSED 0x8000

/* ChangeNotify flags. */
#define FILE_NOTIFY_CHANGE_FILE        0x001
#define FILE_NOTIFY_CHANGE_DIR_NAME    0x002
#define FILE_NOTIFY_CHANGE_ATTRIBUTES  0x004
#define FILE_NOTIFY_CHANGE_SIZE        0x008
#define FILE_NOTIFY_CHANGE_LAST_WRITE  0x010
#define FILE_NOTIFY_CHANGE_LAST_ACCESS 0x020
#define FILE_NOTIFY_CHANGE_CREATION    0x040
#define FILE_NOTIFY_CHANGE_EA          0x080
#define FILE_NOTIFY_CHANGE_SECURITY    0x100
#define FILE_NOTIFY_CHANGE_FILE_NAME   0x200

/* change notify action results */
#define NOTIFY_ACTION_ADDED 1
#define NOTIFY_ACTION_REMOVED 2
#define NOTIFY_ACTION_MODIFIED 3
#define NOTIFY_ACTION_OLD_NAME 4
#define NOTIFY_ACTION_NEW_NAME 5
#define NOTIFY_ACTION_ADDED_STREAM 6
#define NOTIFY_ACTION_REMOVED_STREAM 7
#define NOTIFY_ACTION_MODIFIED_STREAM 8

/* seek modes for smb_seek */
#define SEEK_MODE_START   0
#define SEEK_MODE_CURRENT 1
#define SEEK_MODE_END     2

/* where to find the base of the SMB packet proper */
/* REWRITE TODO: smb_base needs to be removed */
#define smb_base(buf) (((char *)(buf))+4)

/* we don't allow server strings to be longer than 48 characters as
   otherwise NT will not honour the announce packets */
#define MAX_SERVER_STRING_LENGTH 48


#define SMB_SUCCESS 0  /* The request was successful. */

#ifdef WITH_DFS
void dfs_unlogin(void);
extern int dcelogin_atmost_once;
#endif

#ifdef NOSTRDUP
char *strdup(char *s);
#endif

#ifndef SIGNAL_CAST
#define SIGNAL_CAST (RETSIGTYPE (*)(int))
#endif

#ifndef SELECT_CAST
#define SELECT_CAST
#endif

/* these are used in NetServerEnum to choose what to receive */
#define SV_TYPE_WORKSTATION         0x00000001
#define SV_TYPE_SERVER              0x00000002
#define SV_TYPE_SQLSERVER           0x00000004
#define SV_TYPE_DOMAIN_CTRL         0x00000008
#define SV_TYPE_DOMAIN_BAKCTRL      0x00000010
#define SV_TYPE_TIME_SOURCE         0x00000020
#define SV_TYPE_AFP                 0x00000040
#define SV_TYPE_NOVELL              0x00000080
#define SV_TYPE_DOMAIN_MEMBER       0x00000100
#define SV_TYPE_PRINTQ_SERVER       0x00000200
#define SV_TYPE_DIALIN_SERVER       0x00000400
#define SV_TYPE_SERVER_UNIX         0x00000800
#define SV_TYPE_NT                  0x00001000
#define SV_TYPE_WFW                 0x00002000
#define SV_TYPE_SERVER_MFPN         0x00004000
#define SV_TYPE_SERVER_NT           0x00008000
#define SV_TYPE_POTENTIAL_BROWSER   0x00010000
#define SV_TYPE_BACKUP_BROWSER      0x00020000
#define SV_TYPE_MASTER_BROWSER      0x00040000
#define SV_TYPE_DOMAIN_MASTER       0x00080000
#define SV_TYPE_SERVER_OSF          0x00100000
#define SV_TYPE_SERVER_VMS          0x00200000
#define SV_TYPE_WIN95_PLUS          0x00400000
#define SV_TYPE_DFS_SERVER	    0x00800000
#define SV_TYPE_ALTERNATE_XPORT     0x20000000  
#define SV_TYPE_LOCAL_LIST_ONLY     0x40000000  
#define SV_TYPE_DOMAIN_ENUM         0x80000000
#define SV_TYPE_ALL                 0xFFFFFFFF  

/* This was set by JHT in liaison with Jeremy Allison early 1997
 * History:
 * Version 4.0 - never made public
 * Version 4.10 - New to 1.9.16p2, lost in space 1.9.16p3 to 1.9.16p9
 *              - Reappeared in 1.9.16p11 with fixed smbd services
 * Version 4.20 - To indicate that nmbd and browsing now works better
 * Version 4.50 - Set at release of samba-2.2.0 by JHT
 *
 *  Note: In the presence of NT4.X do not set above 4.9
 *        Setting this above 4.9 can have undesired side-effects.
 *        This may change again in Samba-3.0 after further testing. JHT
 */
 
#define DEFAULT_MAJOR_VERSION 0x04
#define DEFAULT_MINOR_VERSION 0x09

/* Browser Election Values */
#define BROWSER_ELECTION_VERSION	0x010f
#define BROWSER_CONSTANT	0xaa55

/* Sercurity mode bits. */
#define NEGOTIATE_SECURITY_USER_LEVEL		0x01
#define NEGOTIATE_SECURITY_CHALLENGE_RESPONSE	0x02
#define NEGOTIATE_SECURITY_SIGNATURES_ENABLED	0x04
#define NEGOTIATE_SECURITY_SIGNATURES_REQUIRED	0x08

/* NT Flags2 bits - cifs6.txt section 3.1.2 */
   
#define FLAGS2_LONG_PATH_COMPONENTS    0x0001
#define FLAGS2_EXTENDED_ATTRIBUTES     0x0002
#define FLAGS2_SMB_SECURITY_SIGNATURES 0x0004
#define FLAGS2_IS_LONG_NAME            0x0040
#define FLAGS2_EXTENDED_SECURITY       0x0800 
#define FLAGS2_DFS_PATHNAMES           0x1000
#define FLAGS2_READ_PERMIT_NO_EXECUTE  0x2000
#define FLAGS2_32_BIT_ERROR_CODES      0x4000 
#define FLAGS2_UNICODE_STRINGS         0x8000

#define FLAGS2_WIN2K_SIGNATURE         0xC852 /* Hack alert ! For now... JRA. */

/* Capabilities.  see ftp.microsoft.com/developr/drg/cifs/cifs/cifs4.txt */

#define CAP_RAW_MODE         0x0001
#define CAP_MPX_MODE         0x0002
#define CAP_UNICODE          0x0004
#define CAP_LARGE_FILES      0x0008
#define CAP_NT_SMBS          0x0010
#define CAP_RPC_REMOTE_APIS  0x0020
#define CAP_STATUS32         0x0040
#define CAP_LEVEL_II_OPLOCKS 0x0080
#define CAP_LOCK_AND_READ    0x0100
#define CAP_NT_FIND          0x0200
#define CAP_DFS              0x1000
#define CAP_W2K_SMBS         0x2000
#define CAP_LARGE_READX      0x4000
#define CAP_LARGE_WRITEX     0x8000
#define CAP_UNIX             0x800000 /* Capabilities for UNIX extensions. Created by HP. */
#define CAP_EXTENDED_SECURITY 0x80000000

/*
 * Global value meaing that the smb_uid field should be
 * ingored (in share level security and protocol level == CORE)
 */

#define UID_FIELD_INVALID 0
#define VUID_OFFSET 100 /* Amount to bias returned vuid numbers */

/* Lock types. */
#define LOCKING_ANDX_SHARED_LOCK 0x1
#define LOCKING_ANDX_OPLOCK_RELEASE 0x2
#define LOCKING_ANDX_CHANGE_LOCKTYPE 0x4
#define LOCKING_ANDX_CANCEL_LOCK 0x8
#define LOCKING_ANDX_LARGE_FILES 0x10

/* Oplock levels */
#define OPLOCKLEVEL_NONE 0
#define OPLOCKLEVEL_II 1

/*
 * Bits we test with.
 */

#define NO_OPLOCK 0
#define EXCLUSIVE_OPLOCK 1
#define BATCH_OPLOCK 2
#define LEVEL_II_OPLOCK 4

#define CORE_OPLOCK_GRANTED (1<<5)
#define EXTENDED_OPLOCK_GRANTED (1<<15)

/*
 * Return values for oplock types.
 */

#define NO_OPLOCK_RETURN 0
#define EXCLUSIVE_OPLOCK_RETURN 1
#define BATCH_OPLOCK_RETURN 2
#define LEVEL_II_OPLOCK_RETURN 3

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
	char         name[17];
	char         scope[64];
	unsigned int name_type;
};


/* A netbios node status array element. */
struct node_status {
	char name[16];
	unsigned char type;
	unsigned char flags;
};

struct pwd_info
{
	BOOL null_pwd;
	BOOL cleartext;
	BOOL crypted;

	fstring password;

	uchar smb_lm_pwd[16];
	uchar smb_nt_pwd[16];

	uchar smb_lm_owf[24];
	uchar smb_nt_owf[128];
	size_t nt_owf_len;

	uchar lm_cli_chal[8];
	uchar nt_cli_chal[128];
	size_t nt_cli_chal_len;

	uchar sess_key[16];
};

#include "rpc_secdes.h"

typedef struct user_struct
{
	struct user_struct *next, *prev;
	uint16 vuid; /* Tag for this entry. */

	DATA_BLOB session_key;

	char *session_keystr; /* used by utmp and pam session code.  
				 TDB key string */
	int homes_snum;

	struct auth_serversupplied_info *server_info;

} user_struct;

struct unix_error_map {
	int unix_error;
	int dos_class;
	int dos_code;
	NTSTATUS nt_error;
};

#include "client.h"

/*
 * Size of new password account encoding string.  This is enough space to
 * hold 11 ACB characters, plus the surrounding [] and a terminating null.
 * Do not change unless you are adding new ACB bits!
 */

#define NEW_PW_FORMAT_SPACE_PADDED_LEN 14

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

/* The maximum length of a trust account password.
   Used when we randomly create it, 15 char passwords
   exceed NT4's max password length */

#define DEFAULT_TRUST_ACCOUNT_PASSWORD_LENGTH 14


/* a set of flags to control handling of request structures */
#define REQ_CONTROL_PROTECTED (1<<0) /* don't destroy this request */
#define REQ_CONTROL_LARGE     (1<<1) /* allow replies larger than max_xmit */
#define REQ_CONTROL_ASYNC     (1<<2) /* the backend will answer this one later */

/* passed to br lock code */
enum brl_type {READ_LOCK, WRITE_LOCK, PENDING_LOCK};

#include "popt_common.h"

#endif /* _SMB_H */
