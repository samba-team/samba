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
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef _SMB_H
#define _SMB_H

#include "libcli/smb/smb_common.h"
#include "libds/common/roles.h"

/* logged when starting the various Samba daemons */
#define COPYRIGHT_STARTUP_MESSAGE	"Copyright Andrew Tridgell and the Samba Team 1992-2014"

#define SAFETY_MARGIN 1024
#define LARGE_WRITEX_HDR_SIZE 65
#define LARGE_WRITEX_BUFFER_SIZE (128*1024)

#define NMB_PORT 137
#define DGRAM_PORT 138
#define NBT_SMB_PORT  139   /* Port for SMB over NBT transport (IETF STD#19). */
#define TCP_SMB_PORT  445   /* Port for SMB over naked TCP transport.         */
#define SMB_PORTS "445 139"

#define Undefined (-1)
#define False false
#define True true
#define Auto (2)
#define Required (3)

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
#define STR_TERMINATE_ASCII 128

/* how long to wait for secondary SMB packets (milli-seconds) */
#define SMB_SECONDARY_WAIT (60*1000)

#define DIR_STRUCT_SIZE 43

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
#define DOS_OPEN_EXEC 3
#define DOS_OPEN_FCB 0xF

/* define shifts and masks for share and open modes. */
#define OPENX_MODE_MASK 0xF
#define DENY_MODE_SHIFT 4
#define DENY_MODE_MASK 0x7
#define GET_OPENX_MODE(x) ((x) & OPENX_MODE_MASK)
#define SET_OPENX_MODE(x) ((x) & OPENX_MODE_MASK)
#define GET_DENY_MODE(x) (((x)>>DENY_MODE_SHIFT) & DENY_MODE_MASK)
#define SET_DENY_MODE(x) (((x) & DENY_MODE_MASK) <<DENY_MODE_SHIFT)

/* Sync on open file (not sure if used anymore... ?) */
#define FILE_SYNC_OPENMODE (1<<14)
#define GET_FILE_SYNC_OPENMODE(x) (((x) & FILE_SYNC_OPENMODE) ? True : False)

/* open disposition values */
#define OPENX_FILE_EXISTS_FAIL 0
#define OPENX_FILE_EXISTS_OPEN 1
#define OPENX_FILE_EXISTS_TRUNCATE 2

/* mask for open disposition. */
#define OPENX_FILE_OPEN_MASK 0x3

#define GET_FILE_OPENX_DISPOSITION(x) ((x) & FILE_OPEN_MASK)
#define SET_FILE_OPENX_DISPOSITION(x) ((x) & FILE_OPEN_MASK)

/* The above can be OR'ed with... */
#define OPENX_FILE_CREATE_IF_NOT_EXIST 0x10
#define OPENX_FILE_FAIL_IF_NOT_EXIST 0

/* pipe string names */

#ifndef MAXSUBAUTHS
#define MAXSUBAUTHS 15 /* max sub authorities in a SID */
#endif

#define SID_MAX_SIZE ((size_t)(8+(MAXSUBAUTHS*4)))

#include "librpc/gen_ndr/security.h"

struct idle_event;
struct share_mode_entry;
struct uuid;
struct named_mutex;
struct wb_context;
struct rpc_cli_smbd_conn;
struct fncall_context;

/* the basic packet size, assuming no words or bytes */
#define smb_size 39

struct notify_change {
	uint32_t action;
	const char *name;
};

struct notify_mid_map;
struct notify_db_entry;
struct notify_event;
struct notify_change_request;
struct sys_notify_backend;
struct sys_notify_context {
	struct tevent_context *ev;
	void *private_data; 	/* For use by the system backend */
};

#include "ntquotas.h"
#include "sysquotas.h"

/* Include VFS stuff */

#include "smb_acls.h"
#include "lib/readdir_attr.h"
#include "vfs.h"

struct current_user {
	struct connection_struct *conn;
	uint64_t vuid; /* SMB2 compat */
	struct security_unix_token ut;
	struct security_token *nt_user_token;
};

/* Defines for the sent_oplock_break field above. */
#define NO_BREAK_SENT 0
#define BREAK_TO_NONE_SENT 1
#define LEVEL_II_BREAK_SENT 2

typedef struct {
	fstring smb_name; /* user name from the client */
	fstring unix_name; /* unix user name of a validated user */
	fstring domain; /* domain that the client specified */
} userdom_struct;

/* used for network interfaces */
struct interface {
	struct interface *next, *prev;
	char *name;
	int flags;
	struct sockaddr_storage ip;
	struct sockaddr_storage netmask;
	struct sockaddr_storage bcast;
};

#define SHARE_MODE_FLAG_POSIX_OPEN	0x1

#include "librpc/gen_ndr/server_id.h"

/* oplock break message definition - linearization of share_mode_entry.

Offset  Data			length.
0	struct server_id pid	4
4	uint16 op_mid		8
12	uint16 op_type		2
14	uint32 access_mask	4
18	uint32 share_access	4
22	uint32 private_options	4
26	uint32 time sec		4
30	uint32 time usec	4
34	uint64 dev		8 bytes
42	uint64 inode		8 bytes
50	uint64 extid		8 bytes
58	unsigned long file_id	4 bytes
62	uint32 uid		4 bytes
66	uint16 flags		2 bytes
68	uint32 name_hash	4 bytes
72

*/

#define OP_BREAK_MSG_PID_OFFSET 0
#define OP_BREAK_MSG_MID_OFFSET 4
#define OP_BREAK_MSG_OP_TYPE_OFFSET 12
#define OP_BREAK_MSG_ACCESS_MASK_OFFSET 14
#define OP_BREAK_MSG_SHARE_ACCESS_OFFSET 18
#define OP_BREAK_MSG_PRIV_OFFSET 22
#define OP_BREAK_MSG_TIME_SEC_OFFSET 26
#define OP_BREAK_MSG_TIME_USEC_OFFSET 30
#define OP_BREAK_MSG_DEV_OFFSET 34
#define OP_BREAK_MSG_INO_OFFSET 42
#define OP_BREAK_MSG_EXTID_OFFSET 50
#define OP_BREAK_MSG_FILE_ID_OFFSET 58
#define OP_BREAK_MSG_UID_OFFSET 62
#define OP_BREAK_MSG_FLAGS_OFFSET 66
#define OP_BREAK_MSG_NAME_HASH_OFFSET 68

#define OP_BREAK_MSG_VNN_OFFSET 72
#define MSG_SMB_SHARE_MODE_ENTRY_SIZE 76

#define NT_HASH_LEN 16
#define LM_HASH_LEN 16

/* offsets into message for common items */
#define smb_com		(NBT_HDR_SIZE+HDR_COM)
#define smb_rcls	(NBT_HDR_SIZE+HDR_RCLS)
#define smb_reh		(NBT_HDR_SIZE+HDR_REH)
#define smb_err		(NBT_HDR_SIZE+HDR_ERR)
#define smb_flg		(NBT_HDR_SIZE+HDR_FLG)
#define smb_flg2	(NBT_HDR_SIZE+HDR_FLG2)
#define smb_pidhigh	(NBT_HDR_SIZE+HDR_PIDHIGH)
#define smb_ss_field	(NBT_HDR_SIZE+HDR_SS_FIELD)
#define smb_tid		(NBT_HDR_SIZE+HDR_TID)
#define smb_pid		(NBT_HDR_SIZE+HDR_PID)
#define smb_uid		(NBT_HDR_SIZE+HDR_UID)
#define smb_mid		(NBT_HDR_SIZE+HDR_MID)
#define smb_wct		(NBT_HDR_SIZE+HDR_WCT)
#define smb_vwv		(NBT_HDR_SIZE+HDR_VWV)
#define smb_vwv0	(smb_vwv+( 0*2))
#define smb_vwv1	(smb_vwv+( 1*2))
#define smb_vwv2	(smb_vwv+( 2*2))
#define smb_vwv3	(smb_vwv+( 3*2))
#define smb_vwv4	(smb_vwv+( 4*2))
#define smb_vwv5	(smb_vwv+( 5*2))
#define smb_vwv6	(smb_vwv+( 6*2))
#define smb_vwv7	(smb_vwv+( 7*2))
#define smb_vwv8	(smb_vwv+( 8*2))
#define smb_vwv9	(smb_vwv+( 9*2))
#define smb_vwv10	(smb_vwv+(10*2))
#define smb_vwv11	(smb_vwv+(11*2))
#define smb_vwv12	(smb_vwv+(12*2))
#define smb_vwv13	(smb_vwv+(13*2))
#define smb_vwv14	(smb_vwv+(14*2))
#define smb_vwv15	(smb_vwv+(15*2))
#define smb_vwv16	(smb_vwv+(16*2))
#define smb_vwv17	(smb_vwv+(17*2))

/* These are the NT transact_get_user_quota sub commands */
#define TRANSACT_GET_USER_QUOTA_LIST_CONTINUE	0x0000
#define TRANSACT_GET_USER_QUOTA_LIST_START	0x0100
#define TRANSACT_GET_USER_QUOTA_FOR_SID		0x0101

/* Relevant IOCTL codes */
#define IOCTL_QUERY_JOB_INFO      0x530060

/* these are the trans2 sub fields for primary requests */
#define smb_tpscnt smb_vwv0
#define smb_tdscnt smb_vwv1
#define smb_mprcnt smb_vwv2
#define smb_mdrcnt smb_vwv3
#define smb_msrcnt smb_vwv4
#define smb_flags smb_vwv5
#define smb_timeout smb_vwv6
#define smb_pscnt smb_vwv9
#define smb_psoff smb_vwv10
#define smb_dscnt smb_vwv11
#define smb_dsoff smb_vwv12
#define smb_suwcnt smb_vwv13
#define smb_setup smb_vwv14
#define smb_setup0 smb_setup
#define smb_setup1 (smb_setup+2)
#define smb_setup2 (smb_setup+4)

/* these are for the secondary requests */
#define smb_spscnt smb_vwv2
#define smb_spsoff smb_vwv3
#define smb_spsdisp smb_vwv4
#define smb_sdscnt smb_vwv5
#define smb_sdsoff smb_vwv6
#define smb_sdsdisp smb_vwv7
#define smb_sfid smb_vwv8

/* and these for responses */
#define smb_tprcnt smb_vwv0
#define smb_tdrcnt smb_vwv1
#define smb_prcnt smb_vwv3
#define smb_proff smb_vwv4
#define smb_prdisp smb_vwv5
#define smb_drcnt smb_vwv6
#define smb_droff smb_vwv7
#define smb_drdisp smb_vwv8

/* these are for the NT trans primary request. */
#define smb_nt_MaxSetupCount smb_vwv0
#define smb_nt_Flags (smb_vwv0 + 1)
#define smb_nt_TotalParameterCount (smb_vwv0 + 3)
#define smb_nt_TotalDataCount (smb_vwv0 + 7)
#define smb_nt_MaxParameterCount (smb_vwv0 + 11)
#define smb_nt_MaxDataCount (smb_vwv0 + 15)
#define smb_nt_ParameterCount (smb_vwv0 + 19)
#define smb_nt_ParameterOffset (smb_vwv0 + 23)
#define smb_nt_DataCount (smb_vwv0 + 27)
#define smb_nt_DataOffset (smb_vwv0 + 31)
#define smb_nt_SetupCount (smb_vwv0 + 35)
#define smb_nt_Function (smb_vwv0 + 36)
#define smb_nt_SetupStart (smb_vwv0 + 38)

/* these are for the NT trans secondary request. */
#define smb_nts_TotalParameterCount (smb_vwv0 + 3)
#define smb_nts_TotalDataCount (smb_vwv0 + 7)
#define smb_nts_ParameterCount (smb_vwv0 + 11)
#define smb_nts_ParameterOffset (smb_vwv0 + 15)
#define smb_nts_ParameterDisplacement (smb_vwv0 + 19)
#define smb_nts_DataCount (smb_vwv0 + 23)
#define smb_nts_DataOffset (smb_vwv0 + 27)
#define smb_nts_DataDisplacement (smb_vwv0 + 31)

/* these are for the NT trans reply. */
#define smb_ntr_TotalParameterCount (smb_vwv0 + 3)
#define smb_ntr_TotalDataCount (smb_vwv0 + 7)
#define smb_ntr_ParameterCount (smb_vwv0 + 11)
#define smb_ntr_ParameterOffset (smb_vwv0 + 15)
#define smb_ntr_ParameterDisplacement (smb_vwv0 + 19)
#define smb_ntr_DataCount (smb_vwv0 + 23)
#define smb_ntr_DataOffset (smb_vwv0 + 27)
#define smb_ntr_DataDisplacement (smb_vwv0 + 31)

/* these are for the NT create_and_X */
#define smb_ntcreate_NameLength (smb_vwv0 + 5)
#define smb_ntcreate_Flags (smb_vwv0 + 7)
#define smb_ntcreate_RootDirectoryFid (smb_vwv0 + 11)
#define smb_ntcreate_DesiredAccess (smb_vwv0 + 15)
#define smb_ntcreate_AllocationSize (smb_vwv0 + 19)
#define smb_ntcreate_FileAttributes (smb_vwv0 + 27)
#define smb_ntcreate_ShareAccess (smb_vwv0 + 31)
#define smb_ntcreate_CreateDisposition (smb_vwv0 + 35)
#define smb_ntcreate_CreateOptions (smb_vwv0 + 39)
#define smb_ntcreate_ImpersonationLevel (smb_vwv0 + 43)
#define smb_ntcreate_SecurityFlags (smb_vwv0 + 47)

/* Named pipe write mode flags. Used in writeX calls. */
#define PIPE_RAW_MODE 0x4
#define PIPE_START_MESSAGE 0x8

/* the desired access to use when opening a pipe */
#define DESIRED_ACCESS_PIPE 0x2019f
 
/* Mapping of access rights to UNIX perms. */
#define UNIX_ACCESS_RWX		FILE_GENERIC_ALL
#define UNIX_ACCESS_R 		FILE_GENERIC_READ
#define UNIX_ACCESS_W		FILE_GENERIC_WRITE
#define UNIX_ACCESS_X		FILE_GENERIC_EXECUTE

/* Mapping of access rights to UNIX perms. for a UNIX directory. */
#define UNIX_DIRECTORY_ACCESS_RWX		FILE_GENERIC_ALL
#define UNIX_DIRECTORY_ACCESS_R 		FILE_GENERIC_READ
#define UNIX_DIRECTORY_ACCESS_W			(FILE_GENERIC_WRITE|FILE_DELETE_CHILD)
#define UNIX_DIRECTORY_ACCESS_X			FILE_GENERIC_EXECUTE

#if 0
/*
 * This is the old mapping we used to use. To get W2KSP2 profiles
 * working we need to map to the canonical file perms.
 */
#define UNIX_ACCESS_RWX (UNIX_ACCESS_R|UNIX_ACCESS_W|UNIX_ACCESS_X)
#define UNIX_ACCESS_R (READ_CONTROL_ACCESS|SYNCHRONIZE_ACCESS|\
			FILE_READ_ATTRIBUTES|FILE_READ_EA|FILE_READ_DATA)
#define UNIX_ACCESS_W (READ_CONTROL_ACCESS|SYNCHRONIZE_ACCESS|\
			FILE_WRITE_ATTRIBUTES|FILE_WRITE_EA|\
			FILE_APPEND_DATA|FILE_WRITE_DATA)
#define UNIX_ACCESS_X (READ_CONTROL_ACCESS|SYNCHRONIZE_ACCESS|\
			FILE_EXECUTE|FILE_READ_ATTRIBUTES)
#endif

#define UNIX_ACCESS_NONE (WRITE_OWNER_ACCESS)

/* Flags field. */
#define REQUEST_OPLOCK 2
#define REQUEST_BATCH_OPLOCK 4
#define OPEN_DIRECTORY 8
#define EXTENDED_RESPONSE_REQUIRED 0x10

#define NTCREATEX_OPTIONS_MUST_IGNORE_MASK      (0x008F0480)

#define NTCREATEX_OPTIONS_INVALID_PARAM_MASK    (0xFF100030)

/*
 * Private create options used by the ntcreatex processing code. From Samba4.
 * We reuse some ignored flags for private use. Passed in the private_flags
 * argument.
 */
#define NTCREATEX_OPTIONS_PRIVATE_DENY_DOS     0x0001
#define NTCREATEX_OPTIONS_PRIVATE_DENY_FCB     0x0002

/* Private options for streams support */
#define NTCREATEX_OPTIONS_PRIVATE_STREAM_DELETE 0x0004

/* Private options for printer support */
#define NTCREATEX_OPTIONS_PRIVATE_DELETE_ON_CLOSE 0x0008

/* Flag for NT transact rename call. */
#define RENAME_REPLACE_IF_EXISTS 1

/* flags for SMBntrename call (from Samba4) */
#define RENAME_FLAG_MOVE_CLUSTER_INFORMATION 0x102 /* ???? */
#define RENAME_FLAG_HARD_LINK                0x103
#define RENAME_FLAG_RENAME                   0x104
#define RENAME_FLAG_COPY                     0x105

/* ChangeNotify flags. */
#define FILE_NOTIFY_CHANGE_FILE_NAME   0x001
#define FILE_NOTIFY_CHANGE_DIR_NAME    0x002
#define FILE_NOTIFY_CHANGE_ATTRIBUTES  0x004
#define FILE_NOTIFY_CHANGE_SIZE        0x008
#define FILE_NOTIFY_CHANGE_LAST_WRITE  0x010
#define FILE_NOTIFY_CHANGE_LAST_ACCESS 0x020
#define FILE_NOTIFY_CHANGE_CREATION    0x040
#define FILE_NOTIFY_CHANGE_EA          0x080
#define FILE_NOTIFY_CHANGE_SECURITY    0x100
#define FILE_NOTIFY_CHANGE_STREAM_NAME	0x00000200
#define FILE_NOTIFY_CHANGE_STREAM_SIZE	0x00000400
#define FILE_NOTIFY_CHANGE_STREAM_WRITE	0x00000800

#define FILE_NOTIFY_CHANGE_NAME \
	(FILE_NOTIFY_CHANGE_FILE_NAME|FILE_NOTIFY_CHANGE_DIR_NAME)

#define FILE_NOTIFY_CHANGE_ALL \
	(FILE_NOTIFY_CHANGE_FILE_NAME   | FILE_NOTIFY_CHANGE_DIR_NAME | \
	 FILE_NOTIFY_CHANGE_ATTRIBUTES  | FILE_NOTIFY_CHANGE_SIZE | \
	 FILE_NOTIFY_CHANGE_LAST_WRITE  | FILE_NOTIFY_CHANGE_LAST_ACCESS | \
	 FILE_NOTIFY_CHANGE_CREATION    | FILE_NOTIFY_CHANGE_EA | \
	 FILE_NOTIFY_CHANGE_SECURITY	| FILE_NOTIFY_CHANGE_STREAM_NAME | \
	 FILE_NOTIFY_CHANGE_STREAM_SIZE | FILE_NOTIFY_CHANGE_STREAM_WRITE)

/* change notify action results */
#define NOTIFY_ACTION_ADDED 1
#define NOTIFY_ACTION_REMOVED 2
#define NOTIFY_ACTION_MODIFIED 3
#define NOTIFY_ACTION_OLD_NAME 4
#define NOTIFY_ACTION_NEW_NAME 5
#define NOTIFY_ACTION_ADDED_STREAM 6
#define NOTIFY_ACTION_REMOVED_STREAM 7
#define NOTIFY_ACTION_MODIFIED_STREAM 8

/*
 * Timestamp format used in "previous versions":
 * This is the windows-level format of the @GMT- token.
 * It is a fixed format not to be confused with the
 * format for the POSIX-Level token of the shadow_copy2
 * VFS module that can be configured via the "shadow:format"
 * configuration option but defaults to the same format.
 * See the shadow_copy2 module.
 */
#define GMT_NAME_LEN 24 /* length of a @GMT- name */
#define GMT_FORMAT "@GMT-%Y.%m.%d-%H.%M.%S"

/* where to find the base of the SMB packet proper */
#define smb_base(buf) (((const char *)(buf))+4)

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

#ifndef SELECT_CAST
#define SELECT_CAST
#endif

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
 *
 * Version 6.1 - For older smb server versions, MMC doesn't let offline
 *               settings to be configured during share creation. Changing
 *               it to 6.1 to mimic Win2K8R2.
 *
 */
 
#define SAMBA_MAJOR_NBT_ANNOUNCE_VERSION 0x06
#define SAMBA_MINOR_NBT_ANNOUNCE_VERSION 0x01

/* Browser Election Values */
#define BROWSER_ELECTION_VERSION	0x010f
#define BROWSER_CONSTANT	0xaa55

/* File Status Flags. See:

http://msdn.microsoft.com/en-us/library/cc246334(PROT.13).aspx
*/

#define NO_EAS			0x1
#define NO_SUBSTREAMS		0x2
#define NO_REPARSETAG		0x4

/* Remote architectures we know about. */
enum remote_arch_types {RA_UNKNOWN, RA_WFWG, RA_OS2, RA_WIN95, RA_WINNT,
			RA_WIN2K, RA_WINXP, RA_WIN2K3, RA_VISTA,
			RA_SAMBA, RA_CIFSFS, RA_WINXP64, RA_OSX};

/*
 * Global value meaning that the smb_uid field should be
 * ingored (in share level security and protocol level == CORE)
 */

#define UID_FIELD_INVALID 0
#define VUID_OFFSET 100 /* Amount to bias returned vuid numbers */

#define TID_FIELD_INVALID 0

#define FNUM_FIELD_INVALID 0

/* 
 * Size of buffer to use when moving files across filesystems. 
 */
#define COPYBUF_SIZE (8*1024)

/*
 * Map the Core and Extended Oplock requesst bits down
 * to common bits (EXCLUSIVE_OPLOCK & BATCH_OPLOCK).
 */

/*
 * Core protocol.
 */
#define CORE_OPLOCK_REQUEST(inbuf) \
    ((CVAL(inbuf,smb_flg)&(FLAG_REQUEST_OPLOCK|FLAG_REQUEST_BATCH_OPLOCK))>>5)

/*
 * Extended protocol.
 */
#define EXTENDED_OPLOCK_REQUEST(inbuf) ((SVAL(inbuf,smb_vwv2)&((1<<1)|(1<<2)))>>1)

/*
 * Bits we test with.
 * Note these must fit into 16-bits.
 */

#define NO_OPLOCK 			OPLOCK_NONE
#define EXCLUSIVE_OPLOCK 		OPLOCK_EXCLUSIVE
#define BATCH_OPLOCK 			OPLOCK_BATCH
#define LEVEL_II_OPLOCK 		OPLOCK_LEVEL_II
#define LEASE_OPLOCK			0x100

/* The following are Samba-private. */
#define INTERNAL_OPEN_ONLY 		0x8
/* #define FAKE_LEVEL_II_OPLOCK 	0x10 */	  /* Not used anymore */
				/* Client requested no_oplock, but we have to
				 * inform potential level2 holders on
				 * write. */
/* #define DEFERRED_OPEN_ENTRY 		0x20 */   /* Not used anymore */
/* #define UNUSED_SHARE_MODE_ENTRY 	0x40 */   /* Not used anymore */
/* #define FORCE_OPLOCK_BREAK_TO_NONE 	0x80 */   /* Not used anymore */

/* None of the following should ever appear in fsp->oplock_request. */
#define SAMBA_PRIVATE_OPLOCK_MASK (INTERNAL_OPEN_ONLY)

#define EXCLUSIVE_OPLOCK_TYPE(lck) ((lck) & ((unsigned int)EXCLUSIVE_OPLOCK|(unsigned int)BATCH_OPLOCK))
#define BATCH_OPLOCK_TYPE(lck) ((lck) & (unsigned int)BATCH_OPLOCK)
#define LEVEL_II_OPLOCK_TYPE(lck) ((lck) & (unsigned int)LEVEL_II_OPLOCK)

/* kernel_oplock_message definition.

struct kernel_oplock_message {
	uint64_t dev;
	uint64_t inode;
	unit64_t extid;
	unsigned long file_id;
};

Offset  Data                  length.
0     uint64_t dev            8 bytes
8     uint64_t inode          8 bytes
16    uint64_t extid          8 bytes
24    unsigned long file_id   4 bytes
28

*/
#define MSG_SMB_KERNEL_BREAK_SIZE 28

/* file_renamed_message definition.

struct file_renamed_message {
	uint64_t dev;
	uint64_t inode;
	char names[1]; A variable area containing sharepath and filename.
};

Offset  Data			length.
0	uint64_t dev		8 bytes
8	uint64_t inode		8 bytes
16      unit64_t extid          8 bytes
24	char [] name		zero terminated namelen bytes
minimum length == 24.

*/

#define MSG_FILE_RENAMED_MIN_SIZE 24

/*
 * On the wire return values for oplock types.
 */

#define CORE_OPLOCK_GRANTED (1<<5)
#define EXTENDED_OPLOCK_GRANTED (1<<15)

#define NO_OPLOCK_RETURN 0
#define EXCLUSIVE_OPLOCK_RETURN 1
#define BATCH_OPLOCK_RETURN 2
#define LEVEL_II_OPLOCK_RETURN 3

/* Oplock levels */
#define OPLOCKLEVEL_NONE 0
#define OPLOCKLEVEL_II 1

/*
 * Capabilities abstracted for different systems.
 */

enum smbd_capability {
    KERNEL_OPLOCK_CAPABILITY,
    DMAPI_ACCESS_CAPABILITY,
    LEASE_CAPABILITY,
    DAC_OVERRIDE_CAPABILITY
};

/*
 * Kernel oplocks capability flags.
 */

/* Level 2 oplocks are supported natively by kernel oplocks. */
#define KOPLOCKS_LEVEL2_SUPPORTED		0x1

/* The kernel notifies deferred openers when they can retry the open. */
#define KOPLOCKS_DEFERRED_OPEN_NOTIFICATION	0x2

/* The kernel notifies smbds when an oplock break times out. */
#define KOPLOCKS_TIMEOUT_NOTIFICATION		0x4

/* The kernel notifies smbds when an oplock is broken. */
#define KOPLOCKS_OPLOCK_BROKEN_NOTIFICATION	0x8

struct kernel_oplocks_ops;
struct kernel_oplocks {
	const struct kernel_oplocks_ops *ops;
	uint32_t flags;
	void *private_data;
};

enum level2_contention_type {
	LEVEL2_CONTEND_ALLOC_SHRINK,
	LEVEL2_CONTEND_ALLOC_GROW,
	LEVEL2_CONTEND_SET_FILE_LEN,
	LEVEL2_CONTEND_FILL_SPARSE,
	LEVEL2_CONTEND_WRITE,
	LEVEL2_CONTEND_WINDOWS_BRL,
	LEVEL2_CONTEND_POSIX_BRL
};

/* if a kernel does support oplocks then a structure of the following
   typee is used to describe how to interact with the kernel */
struct kernel_oplocks_ops {
	bool (*set_oplock)(struct kernel_oplocks *ctx,
			   files_struct *fsp, int oplock_type);
	void (*release_oplock)(struct kernel_oplocks *ctx,
			       files_struct *fsp, int oplock_type);
	void (*contend_level2_oplocks_begin)(files_struct *fsp,
					     enum level2_contention_type type);
	void (*contend_level2_oplocks_end)(files_struct *fsp,
					   enum level2_contention_type type);
};

#include "smb_macros.h"

#define MAX_NETBIOSNAME_LEN 16
/* DOS character, NetBIOS namestring. Type used on the wire. */
typedef char nstring[MAX_NETBIOSNAME_LEN];
/* Unix character, NetBIOS namestring. Type used to manipulate name in nmbd. */
typedef char unstring[MAX_NETBIOSNAME_LEN*4];

/* A netbios name structure. */
struct nmb_name {
	nstring      name;
	char         scope[64];
	unsigned int name_type;
};

/* A netbios node status array element. */
struct node_status {
	nstring name;
	unsigned char type;
	unsigned char flags;
};

/* The extra info from a NetBIOS node status query */
struct node_status_extra {
	unsigned char mac_addr[6];
	/* There really is more here ... */ 
};

#define SAFE_NETBIOS_CHARS ". -_"

/* The maximum length of a trust account password.
   Used when we randomly create it, 15 char passwords
   exceed NT4's max password length */

#define DEFAULT_TRUST_ACCOUNT_PASSWORD_LENGTH 14

#define PORT_NONE	0
#ifndef LDAP_PORT
#define LDAP_PORT	389
#endif
#define LDAP_GC_PORT    3268

/* used by the IP comparison function */
struct ip_service {
	struct sockaddr_storage ss;
	unsigned port;
};

struct ea_struct {
	uint8 flags;
	char *name;
	DATA_BLOB value;
};

struct ea_list {
	struct ea_list *next, *prev;
	struct ea_struct ea;
};

/* EA names used internally in Samba. KEEP UP TO DATE with prohibited_ea_names in trans2.c !. */
#define SAMBA_POSIX_INHERITANCE_EA_NAME "user.SAMBA_PAI"
/* EA to use for DOS attributes */
#define SAMBA_XATTR_DOS_ATTRIB "user.DOSATTRIB"
/* Prefix for DosStreams in the vfs_streams_xattr module */
#define SAMBA_XATTR_DOSSTREAM_PREFIX "user.DosStream."
/* Prefix for xattrs storing streams. */
#define SAMBA_XATTR_MARKER "user.SAMBA_STREAMS"

/* usershare error codes. */
enum usershare_err {
		USERSHARE_OK=0,
		USERSHARE_MALFORMED_FILE,
		USERSHARE_BAD_VERSION,
		USERSHARE_MALFORMED_PATH,
		USERSHARE_MALFORMED_COMMENT_DEF,
		USERSHARE_MALFORMED_ACL_DEF,
		USERSHARE_ACL_ERR,
		USERSHARE_PATH_NOT_ABSOLUTE,
		USERSHARE_PATH_IS_DENIED,
		USERSHARE_PATH_NOT_ALLOWED,
		USERSHARE_PATH_NOT_DIRECTORY,
		USERSHARE_POSIX_ERR,
		USERSHARE_MALFORMED_SHARENAME_DEF,
		USERSHARE_BAD_SHARENAME
};

/* Different reasons for closing a file. */
enum file_close_type {NORMAL_CLOSE=0,SHUTDOWN_CLOSE,ERROR_CLOSE};

/* Used in SMB_FS_OBJECTID_INFORMATION requests.  Must be exactly 48 bytes. */
#define SAMBA_EXTENDED_INFO_MAGIC 0x536d4261 /* "SmBa" */
#define SAMBA_EXTENDED_INFO_VERSION_STRING_LENGTH 28
struct smb_extended_info {
	uint32 samba_magic;		/* Always SAMBA_EXTRA_INFO_MAGIC */
	uint32 samba_version;		/* Major/Minor/Release/Revision */
	uint32 samba_subversion;	/* Prerelease/RC/Vendor patch */
	NTTIME samba_gitcommitdate;
	char   samba_version_string[SAMBA_EXTENDED_INFO_VERSION_STRING_LENGTH];
};

/*
 * Reasons for cache flush.
 */

enum flush_reason_enum {
    SAMBA_SEEK_FLUSH,
    SAMBA_READ_FLUSH,
    SAMBA_WRITE_FLUSH,
    SAMBA_READRAW_FLUSH,
    SAMBA_OPLOCK_RELEASE_FLUSH,
    SAMBA_CLOSE_FLUSH,
    SAMBA_SYNC_FLUSH,
    SAMBA_SIZECHANGE_FLUSH,
    /* NUM_FLUSH_REASONS must remain the last value in the enumeration. */
    SAMBA_NUM_FLUSH_REASONS};

#endif /* _SMB_H */
