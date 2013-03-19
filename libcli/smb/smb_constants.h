/*
   Unix SMB/CIFS implementation.

   SMB parameters and setup, plus a whole lot more.

   Copyright (C) Andrew Tridgell              2011

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

#ifndef _SMB_CONSTANTS_H
#define _SMB_CONSTANTS_H

/*
 * Netbios over TCP (rfc 1002)
 */
#define NBSSmessage     0x00   /* session message */
#define NBSSrequest     0x81   /* session request */
#define NBSSpositive    0x82   /* positiv session response */
#define NBSSnegative    0x83   /* negativ session response */
#define NBSSretarget    0x84   /* retarget session response */
#define NBSSkeepalive   0x85   /* keepalive */

#define SMB_MAGIC 0x424D53FF /* 0xFF 'S' 'M' 'B' */

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

#define smb_len_nbt(buf) (RIVAL(buf, 0) & 0x1FFFF)
#define _smb_setlen_nbt(buf,len) RSIVAL(buf, 0, (len) & 0x1FFFF)
#define smb_setlen_nbt(buf, len) do { \
	_smb_setlen_nbt(buf, len); \
	SIVAL(buf, 4, SMB_MAGIC); \
} while (0)

#define smb_len_tcp(buf) (RIVAL(buf, 0) & 0xFFFFFF)
#define _smb_setlen_tcp(buf,len) RSIVAL(buf, 0, (len) & 0xFFFFFF)
#define smb_setlen_tcp(buf, len) do { \
	_smb_setlen_tcp(buf, len); \
	SIVAL(buf, 4, SMB_MAGIC); \
} while (0)

/* protocol types. It assumes that higher protocols include lower protocols
   as subsets. */
enum protocol_types {
	PROTOCOL_NONE,
	PROTOCOL_CORE,
	PROTOCOL_COREPLUS,
	PROTOCOL_LANMAN1,
	PROTOCOL_LANMAN2,
	PROTOCOL_NT1,
	PROTOCOL_SMB2_02,
	PROTOCOL_SMB2_10,
	PROTOCOL_SMB2_22,
	PROTOCOL_SMB2_24,
	PROTOCOL_SMB3_00
};
#define PROTOCOL_LATEST PROTOCOL_SMB3_00

enum smb_signing_setting {
	SMB_SIGNING_DEFAULT = -1,
	SMB_SIGNING_OFF = 0,
	SMB_SIGNING_IF_REQUIRED = 1,
	SMB_SIGNING_REQUIRED = 3,
};

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
#define SMBcheckpath  0x10   /* check directory path */
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
#define SMBwriteunlock 0x14 /* Unlock a range then write */
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

/* Sercurity mode bits. */
#define NEGOTIATE_SECURITY_USER_LEVEL		0x01
#define NEGOTIATE_SECURITY_CHALLENGE_RESPONSE	0x02
#define NEGOTIATE_SECURITY_SIGNATURES_ENABLED	0x04
#define NEGOTIATE_SECURITY_SIGNATURES_REQUIRED	0x08

/* Capabilities.  see ftp.microsoft.com/developr/drg/cifs/cifs/cifs4.txt */

#define CAP_RAW_MODE		0x00000001
#define CAP_MPX_MODE		0x00000002
#define CAP_UNICODE		0x00000004
#define CAP_LARGE_FILES		0x00000008
#define CAP_NT_SMBS		0x00000010
#define CAP_RPC_REMOTE_APIS	0x00000020
#define CAP_STATUS32		0x00000040
#define CAP_LEVEL_II_OPLOCKS	0x00000080
#define CAP_LOCK_AND_READ	0x00000100
#define CAP_NT_FIND		0x00000200
#define CAP_DFS			0x00001000
#define CAP_W2K_SMBS		0x00002000
#define CAP_LARGE_READX		0x00004000
#define CAP_LARGE_WRITEX	0x00008000
#define CAP_LWIO		0x00010000
#define CAP_UNIX		0x00800000 /* Capabilities for UNIX extensions. Created by HP. */
#define CAP_DYNAMIC_REAUTH	0x20000000
#define CAP_EXTENDED_SECURITY	0x80000000

#define SMB_CAP_BOTH_MASK ( \
	CAP_UNICODE | \
	CAP_NT_SMBS | \
	CAP_STATUS32 | \
	CAP_LEVEL_II_OPLOCKS | \
	CAP_EXTENDED_SECURITY | \
	0)
#define SMB_CAP_SERVER_MASK ( \
	CAP_RAW_MODE | \
	CAP_MPX_MODE | \
	CAP_LARGE_FILES | \
	CAP_RPC_REMOTE_APIS | \
	CAP_LOCK_AND_READ | \
	CAP_NT_FIND | \
	CAP_DFS | \
	CAP_W2K_SMBS | \
	CAP_LARGE_READX | \
	CAP_LARGE_WRITEX | \
	CAP_LWIO | \
	CAP_UNIX | \
	0)
#define SMB_CAP_CLIENT_MASK ( \
	CAP_DYNAMIC_REAUTH | \
	0)
/*
 * Older Samba releases (<= 3.6.x)
 * expect the client to send CAP_LARGE_READX
 * in order to let the client use large reads.
 */
#define SMB_CAP_LEGACY_CLIENT_MASK ( \
	SMB_CAP_CLIENT_MASK | \
	CAP_LARGE_READX | \
	CAP_LARGE_WRITEX | \
	0)

/* Client-side offline caching policy types */
enum csc_policy {
	CSC_POLICY_MANUAL=0,
	CSC_POLICY_DOCUMENTS=1,
	CSC_POLICY_PROGRAMS=2,
	CSC_POLICY_DISABLE=3
};

/* TCONX Flag (smb_vwv2). [MS-SMB] 2.2.4.7.1 */
#define TCONX_FLAG_DISCONNECT_TID       0x0001
#define TCONX_FLAG_EXTENDED_SIGNATURES  0x0004
#define TCONX_FLAG_EXTENDED_RESPONSE	0x0008

/* this is used on a TConX. [MS-SMB] 2.2.4.7.2 */
#define SMB_SUPPORT_SEARCH_BITS        0x0001
#define SMB_SHARE_IN_DFS               0x0002
#define SMB_CSC_MASK                   0x000C
#define SMB_CSC_POLICY_SHIFT           2
#define SMB_UNIQUE_FILE_NAME           0x0010
#define SMB_EXTENDED_SIGNATURES        0x0020

/* NT Flags2 bits - cifs6.txt section 3.1.2 */
#define FLAGS2_LONG_PATH_COMPONENTS    0x0001
#define FLAGS2_EXTENDED_ATTRIBUTES     0x0002
#define FLAGS2_SMB_SECURITY_SIGNATURES 0x0004
#define FLAGS2_SMB_SECURITY_SIGNATURES_REQUIRED 0x0010
#define FLAGS2_IS_LONG_NAME            0x0040
#define FLAGS2_EXTENDED_SECURITY       0x0800
#define FLAGS2_DFS_PATHNAMES           0x1000
#define FLAGS2_READ_PERMIT_EXECUTE     0x2000
#define FLAGS2_32_BIT_ERROR_CODES      0x4000
#define FLAGS2_UNICODE_STRINGS         0x8000
#define FLAGS2_WIN2K_SIGNATURE         0xC852 /* Hack alert ! For now... JRA. */

/* FileAttributes (search attributes) field */
#define FILE_ATTRIBUTE_READONLY		0x0001L
#define FILE_ATTRIBUTE_HIDDEN		0x0002L
#define FILE_ATTRIBUTE_SYSTEM		0x0004L
#define FILE_ATTRIBUTE_VOLUME		0x0008L
#define FILE_ATTRIBUTE_DIRECTORY	0x0010L
#define FILE_ATTRIBUTE_ARCHIVE		0x0020L
#define FILE_ATTRIBUTE_DEVICE		0x0040L
#define FILE_ATTRIBUTE_NORMAL		0x0080L
#define FILE_ATTRIBUTE_TEMPORARY	0x0100L
#define FILE_ATTRIBUTE_SPARSE		0x0200L
#define FILE_ATTRIBUTE_REPARSE_POINT	0x0400L
#define FILE_ATTRIBUTE_COMPRESSED	0x0800L
#define FILE_ATTRIBUTE_OFFLINE		0x1000L
#define FILE_ATTRIBUTE_NONINDEXED	0x2000L
#define FILE_ATTRIBUTE_ENCRYPTED	0x4000L
#define FILE_ATTRIBUTE_ALL_MASK 	0x7FFFL

#define SAMBA_ATTRIBUTES_MASK		(FILE_ATTRIBUTE_READONLY|\
					FILE_ATTRIBUTE_HIDDEN|\
					FILE_ATTRIBUTE_SYSTEM|\
					FILE_ATTRIBUTE_DIRECTORY|\
					FILE_ATTRIBUTE_ARCHIVE)

/* File type flags */
#define FILE_TYPE_DISK  0
#define FILE_TYPE_BYTE_MODE_PIPE 1
#define FILE_TYPE_MESSAGE_MODE_PIPE 2
#define FILE_TYPE_PRINTER 3
#define FILE_TYPE_COMM_DEVICE 4
#define FILE_TYPE_UNKNOWN 0xFFFF

/* Lock types. */
#define LOCKING_ANDX_EXCLUSIVE_LOCK  0x00
#define LOCKING_ANDX_SHARED_LOCK     0x01
#define LOCKING_ANDX_OPLOCK_RELEASE  0x02
#define LOCKING_ANDX_CHANGE_LOCKTYPE 0x04
#define LOCKING_ANDX_CANCEL_LOCK     0x08
#define LOCKING_ANDX_LARGE_FILES     0x10

/*
 * Bits we test with.
 */

#define OPLOCK_NONE      0
#define OPLOCK_EXCLUSIVE 1
#define OPLOCK_BATCH     2
#define OPLOCK_LEVEL_II  4

#define CORE_OPLOCK_GRANTED (1<<5)
#define EXTENDED_OPLOCK_GRANTED (1<<15)

/*
 * Return values for oplock types.
 */

#define NO_OPLOCK_RETURN 0
#define EXCLUSIVE_OPLOCK_RETURN 1
#define BATCH_OPLOCK_RETURN 2
#define LEVEL_II_OPLOCK_RETURN 3

/* oplock levels sent in oplock break */
#define OPLOCK_BREAK_TO_NONE     0
#define OPLOCK_BREAK_TO_LEVEL_II 1


/* ioctl codes */
#define IOCTL_QUERY_JOB_INFO      0x530060

/* filesystem control codes */
#define FSCTL_METHOD_BUFFERED	0x00000000
#define FSCTL_METHOD_IN_DIRECT	0x00000001
#define FSCTL_METHOD_OUT_DIRECT	0x00000002
#define FSCTL_METHOD_NEITHER	0x00000003

#define FSCTL_ACCESS_ANY	0x00000000
#define FSCTL_ACCESS_READ	0x00004000
#define FSCTL_ACCESS_WRITE	0x00008000

#define FSCTL_DFS			0x00060000
#define FSCTL_DFS_GET_REFERRALS		(FSCTL_DFS | FSCTL_ACCESS_ANY | 0x0194 | FSCTL_METHOD_BUFFERED)
#define FSCTL_DFS_GET_REFERRALS_EX	(FSCTL_DFS | FSCTL_ACCESS_ANY | 0x01B0 | FSCTL_METHOD_BUFFERED)

#define FSCTL_FILESYSTEM		0x00090000
#define FSCTL_REQUEST_OPLOCK_LEVEL_1    (FSCTL_FILESYSTEM | FSCTL_ACCESS_ANY | 0x0000 | FSCTL_METHOD_BUFFERED)
#define FSCTL_REQUEST_OPLOCK_LEVEL_2    (FSCTL_FILESYSTEM | FSCTL_ACCESS_ANY | 0x0004 | FSCTL_METHOD_BUFFERED)
#define FSCTL_REQUEST_BATCH_OPLOCK      (FSCTL_FILESYSTEM | FSCTL_ACCESS_ANY | 0x0008 | FSCTL_METHOD_BUFFERED)
#define FSCTL_OPLOCK_BREAK_ACKNOWLEDGE  (FSCTL_FILESYSTEM | FSCTL_ACCESS_ANY | 0x000C | FSCTL_METHOD_BUFFERED)
#define FSCTL_OPBATCH_ACK_CLOSE_PENDING (FSCTL_FILESYSTEM | FSCTL_ACCESS_ANY | 0x0010 | FSCTL_METHOD_BUFFERED)
#define FSCTL_OPLOCK_BREAK_NOTIFY       (FSCTL_FILESYSTEM | FSCTL_ACCESS_ANY | 0x0014 | FSCTL_METHOD_BUFFERED)
#define FSCTL_FILESYS_GET_STATISTICS	(FSCTL_FILESYSTEM | FSCTL_ACCESS_ANY | 0x0060 | FSCTL_METHOD_BUFFERED)
#define FSCTL_GET_NTFS_VOLUME_DATA	(FSCTL_FILESYSTEM | FSCTL_ACCESS_ANY | 0x0064 | FSCTL_METHOD_BUFFERED)
#define FSCTL_IS_VOLUME_DIRTY		(FSCTL_FILESYSTEM | FSCTL_ACCESS_ANY | 0x0078 | FSCTL_METHOD_BUFFERED)
#define FSCTL_FIND_FILES_BY_SID		(FSCTL_FILESYSTEM | FSCTL_ACCESS_ANY | 0x008C | FSCTL_METHOD_NEITHER)
#define FSCTL_SET_OBJECT_ID		(FSCTL_FILESYSTEM | FSCTL_ACCESS_ANY | 0x0098 | FSCTL_METHOD_BUFFERED)
#define FSCTL_GET_OBJECT_ID		(FSCTL_FILESYSTEM | FSCTL_ACCESS_ANY | 0x009C | FSCTL_METHOD_BUFFERED)
#define FSCTL_DELETE_OBJECT_ID		(FSCTL_FILESYSTEM | FSCTL_ACCESS_ANY | 0x00A0 | FSCTL_METHOD_BUFFERED)
#define FSCTL_SET_REPARSE_POINT		(FSCTL_FILESYSTEM | FSCTL_ACCESS_ANY | 0x00A4 | FSCTL_METHOD_BUFFERED)
#define FSCTL_GET_REPARSE_POINT		(FSCTL_FILESYSTEM | FSCTL_ACCESS_ANY | 0x00A8 | FSCTL_METHOD_BUFFERED)
#define FSCTL_DELETE_REPARSE_POINT	(FSCTL_FILESYSTEM | FSCTL_ACCESS_ANY | 0x00AC | FSCTL_METHOD_BUFFERED)
#define FSCTL_CREATE_OR_GET_OBJECT_ID	(FSCTL_FILESYSTEM | FSCTL_ACCESS_ANY | 0x00C0 | FSCTL_METHOD_BUFFERED)
#define FSCTL_SET_SPARSE		(FSCTL_FILESYSTEM | FSCTL_ACCESS_ANY | 0x00C4 | FSCTL_METHOD_BUFFERED)
#define FSCTL_QUERY_ALLOCATED_RANGES	(FSCTL_FILESYSTEM | FSCTL_ACCESS_READ | 0x00CC | FSCTL_METHOD_NEITHER)
#define FSCTL_FILE_LEVEL_TRIM		(FSCTL_FILESYSTEM | FSCTL_ACCESS_WRITE | 0x0208 | FSCTL_METHOD_BUFFERED)
#define FSCTL_OFFLOAD_READ		(FSCTL_FILESYSTEM | FSCTL_ACCESS_READ | 0x0264 | FSCTL_METHOD_BUFFERED)
#define FSCTL_OFFLOAD_WRITE		(FSCTL_FILESYSTEM | FSCTL_ACCESS_WRITE | 0x0268 | FSCTL_METHOD_BUFFERED)

#define FSCTL_NAMED_PIPE		0x00110000
#define FSCTL_PIPE_PEEK			(FSCTL_NAMED_PIPE | FSCTL_ACCESS_READ | 0x000C | FSCTL_METHOD_BUFFERED)
#define FSCTL_NAMED_PIPE_READ_WRITE	(FSCTL_NAMED_PIPE | FSCTL_ACCESS_READ \
							  | FSCTL_ACCESS_WRITE | 0x0014 | FSCTL_METHOD_NEITHER)
#define FSCTL_PIPE_TRANSCEIVE		FSCTL_NAMED_PIPE_READ_WRITE	/* SMB2 function name */
#define FSCTL_PIPE_WAIT			(FSCTL_NAMED_PIPE | FSCTL_ACCESS_ANY | 0x0018 | FSCTL_METHOD_BUFFERED)

#define FSCTL_NETWORK_FILESYSTEM	0x00140000
#define FSCTL_GET_SHADOW_COPY_DATA	(FSCTL_NETWORK_FILESYSTEM | FSCTL_ACCESS_READ | 0x0064 | FSCTL_METHOD_BUFFERED)
#define FSCTL_SRV_ENUM_SNAPS		FSCTL_GET_SHADOW_COPY_DATA	/* SMB2 function name */
#define FSCTL_SRV_REQUEST_RESUME_KEY	(FSCTL_NETWORK_FILESYSTEM | FSCTL_ACCESS_ANY | 0x0078 | FSCTL_METHOD_BUFFERED)
#define FSCTL_SRV_COPYCHUNK		(FSCTL_NETWORK_FILESYSTEM | FSCTL_ACCESS_READ | 0x00F0 | FSCTL_METHOD_OUT_DIRECT)
#define FSCTL_SRV_COPYCHUNK_WRITE	(FSCTL_NETWORK_FILESYSTEM | FSCTL_ACCESS_WRITE | 0x00F0 | FSCTL_METHOD_OUT_DIRECT)
#define FSCTL_SRV_READ_HASH		(FSCTL_NETWORK_FILESYSTEM | FSCTL_ACCESS_READ| 0x01B8 | FSCTL_METHOD_NEITHER)
#define FSCTL_LMR_REQ_RESILIENCY	(FSCTL_NETWORK_FILESYSTEM | FSCTL_ACCESS_ANY | 0x01D4 | FSCTL_METHOD_BUFFERED)
#define FSCTL_LMR_SET_LINK_TRACKING_INFORMATION \
	(FSCTL_NETWORK_FILESYSTEM | FSCTL_ACCESS_ANY | 0x00EC | FSCTL_METHOD_BUFFERED)
#define FSCTL_QUERY_NETWORK_INTERFACE_INFO \
	(FSCTL_NETWORK_FILESYSTEM | FSCTL_ACCESS_ANY | 0x01FC | FSCTL_METHOD_BUFFERED)

/*
 * FSCTL_VALIDATE_NEGOTIATE_INFO_224 was used used in
 * Windows 8 server beta with SMB 2.24
 */
#define FSCTL_VALIDATE_NEGOTIATE_INFO_224 \
	(FSCTL_NETWORK_FILESYSTEM | FSCTL_ACCESS_ANY | 0x0200 | FSCTL_METHOD_BUFFERED)
#define FSCTL_VALIDATE_NEGOTIATE_INFO	(FSCTL_NETWORK_FILESYSTEM | FSCTL_ACCESS_ANY | 0x0204 | FSCTL_METHOD_BUFFERED)

#endif /* _SMB_CONSTANTS_H */
