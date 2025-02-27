/*
   Unix SMB/CIFS implementation.
   SMB transaction2 handling

   Copyright (C) James Peach 2007
   Copyright (C) Jeremy Allison 1994-2002.

   Extensively modified by Andrew Tridgell, 1995

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

#ifndef __SMB_UNIX_EXT_H__
#define __SMB_UNIX_EXT_H__

#include <replace.h>
#include "librpc/gen_ndr/smb3posix.h"

/* UNIX CIFS Extensions - created by HP */
/*
 * UNIX CIFS Extensions have the range 0x200 - 0x2FF reserved.
 * Supposedly Microsoft have agreed to this.
 */

#define MIN_UNIX_INFO_LEVEL 0x200
#define MAX_UNIX_INFO_LEVEL 0x2FF

#define SMB_QUERY_FILE_UNIX_BASIC      0x200   /* UNIX File Info*/
#define SMB_SET_FILE_UNIX_BASIC        0x200
#define SMB_SET_FILE_UNIX_INFO2        0x20B   /* UNIX File Info2 */

#define SMB_MODE_NO_CHANGE                 0xFFFFFFFF     /* file mode value which */
                                              /* means "don't change it" */
#define SMB_UID_NO_CHANGE                  0xFFFFFFFF
#define SMB_GID_NO_CHANGE                  0xFFFFFFFF

#define SMB_SIZE_NO_CHANGE_LO              0xFFFFFFFF
#define SMB_SIZE_NO_CHANGE_HI              0xFFFFFFFF

#define SMB_TIME_NO_CHANGE_LO              0xFFFFFFFF
#define SMB_TIME_NO_CHANGE_HI              0xFFFFFFFF

/*
Offset Size         Name
0      LARGE_INTEGER EndOfFile                File size
8      LARGE_INTEGER Blocks                   Number of bytes used on disk (st_blocks).
16     LARGE_INTEGER CreationTime             Creation time
24     LARGE_INTEGER LastAccessTime           Last access time
32     LARGE_INTEGER LastModificationTime     Last modification time
40     LARGE_INTEGER Uid                      Numeric user id for the owner
48     LARGE_INTEGER Gid                      Numeric group id of owner
56     ULONG Type                             Enumeration specifying the pathname type:
                                              0 -- File
                                              1 -- Directory
                                              2 -- Symbolic link
                                              3 -- Character device
                                              4 -- Block device
                                              5 -- FIFO (named pipe)
                                              6 -- Unix domain socket

60     LARGE_INTEGER devmajor                 Major device number if type is device
68     LARGE_INTEGER devminor                 Minor device number if type is device
76     LARGE_INTEGER uniqueid                 This is a server-assigned unique id for the file. The client
                                              will typically map this onto an inode number. The scope of
                                              uniqueness is the share.
84     LARGE_INTEGER permissions              Standard UNIX file permissions  - see below.
92     LARGE_INTEGER nlinks                   The number of directory entries that map to this entry
                                              (number of hard links)

100 - end.
*/

#define SMB_FILE_UNIX_BASIC_SIZE 100

/* Flags for chflags (CIFS_UNIX_EXTATTR_CAP capability) and
 * SMB_QUERY_FILE_UNIX_INFO2.
 */
#define EXT_SECURE_DELETE               0x00000001
#define EXT_ENABLE_UNDELETE             0x00000002
#define EXT_SYNCHRONOUS                 0x00000004
#define EXT_IMMUTABLE			0x00000008
#define EXT_OPEN_APPEND_ONLY            0x00000010
#define EXT_DO_NOT_BACKUP               0x00000020
#define EXT_NO_UPDATE_ATIME             0x00000040
#define EXT_HIDDEN			0x00000080

#define SMB_QUERY_FILE_UNIX_LINK       0x201
#define SMB_SET_FILE_UNIX_LINK         0x201
#define SMB_SET_FILE_UNIX_HLINK        0x203
/* SMB_QUERY_POSIX_ACL 0x204 see below */
#define SMB_QUERY_XATTR                0x205 /* need for non-user XATTRs */
#define SMB_QUERY_ATTR_FLAGS           0x206 /* chflags, chattr */
#define SMB_SET_ATTR_FLAGS             0x206
#define SMB_QUERY_POSIX_PERMISSION     0x207
/* Only valid for qfileinfo */
#define SMB_QUERY_POSIX_LOCK	       0x208
/* Only valid for setfileinfo */
#define SMB_SET_POSIX_LOCK	       0x208

/* The set info levels for POSIX path operations. */
#define SMB_POSIX_PATH_OPEN	       0x209
#define SMB_POSIX_PATH_UNLINK	       0x20A

#define SMB_QUERY_FILE_UNIX_INFO2      0x20B   /* UNIX File Info2 */
#define SMB_SET_FILE_UNIX_INFO2        0x20B

/*
SMB_QUERY_FILE_UNIX_INFO2 is SMB_QUERY_FILE_UNIX_BASIC with create
time and file flags appended. The corresponding info level for
findfirst/findnext is SMB_FIND_FILE_UNIX_INFO2.
    Size    Offset  Value
    ---------------------
    0      LARGE_INTEGER EndOfFile  File size
    8      LARGE_INTEGER Blocks     Number of blocks used on disk
    16     LARGE_INTEGER ChangeTime Attribute change time
    24     LARGE_INTEGER LastAccessTime           Last access time
    32     LARGE_INTEGER LastModificationTime     Last modification time
    40     LARGE_INTEGER Uid        Numeric user id for the owner
    48     LARGE_INTEGER Gid        Numeric group id of owner
    56     ULONG Type               Enumeration specifying the file type
    60     LARGE_INTEGER devmajor   Major device number if type is device
    68     LARGE_INTEGER devminor   Minor device number if type is device
    76     LARGE_INTEGER uniqueid   This is a server-assigned unique id
    84     LARGE_INTEGER permissions		Standard UNIX permissions
    92     LARGE_INTEGER nlinks			Number of hard links
    100    LARGE_INTEGER CreationTime		Create/birth time
    108    ULONG FileFlags          File flags enumeration
    112    ULONG FileFlagsMask      Mask of valid flags
*/

/* Transact 2 Find First levels */
#define SMB_FIND_FILE_UNIX             0x202
#define SMB_FIND_FILE_UNIX_INFO2       0x20B /* UNIX File Info2 */

#define SMB_FILE_UNIX_INFO2_SIZE 116

/*
 Info level for TRANS2_QFSINFO - returns version of CIFS UNIX extensions, plus
 64-bits worth of capability fun :-).
 Use the same info level for TRANS2_SETFSINFO
*/

#define SMB_QUERY_CIFS_UNIX_INFO      0x200
#define SMB_SET_CIFS_UNIX_INFO        0x200

/* Returns or sets the following.

  UINT16             major version number
  UINT16             minor version number
  LARGE_INTEGER      capability bitfield

*/

#define CIFS_UNIX_MAJOR_VERSION 1
#define CIFS_UNIX_MINOR_VERSION 0

#define CIFS_UNIX_FCNTL_LOCKS_CAP           0x1
#define CIFS_UNIX_POSIX_ACLS_CAP            0x2
#define CIFS_UNIX_XATTTR_CAP	            0x4 /* for support of other xattr
						namespaces such as system,
						security and trusted */
#define CIFS_UNIX_EXTATTR_CAP		    0x8 /* for support of chattr
						(chflags) and lsattr */
#define CIFS_UNIX_POSIX_PATHNAMES_CAP	   0x10 /* Use POSIX pathnames on the wire. */
#define CIFS_UNIX_POSIX_PATH_OPERATIONS_CAP	   0x20 /* We can cope with POSIX open/mkdir/unlink etc. */
#define CIFS_UNIX_LARGE_READ_CAP           0x40 /* We can cope with 24 bit reads in readX. */
#define CIFS_UNIX_LARGE_WRITE_CAP          0x80 /* We can cope with 24 bit writes in writeX. */
#define CIFS_UNIX_TRANSPORT_ENCRYPTION_CAP      0x100 /* We can do SPNEGO negotiations for encryption. */
#define CIFS_UNIX_TRANSPORT_ENCRYPTION_MANDATORY_CAP    0x200 /* We *must* SPNEGO negotiations for encryption. */

#define SMB_QUERY_POSIX_FS_INFO     0x201

/* Returns FILE_SYSTEM_POSIX_INFO struct as follows
      (NB   For undefined values return -1 in that field)
   le32 OptimalTransferSize;    bsize on some os, iosize on other os, This
				is a hint to the client about best size. Server
				can return -1 if no preference, ie if SMB
				negotiated size is adequate for optimal
				read/write performance
   le32 BlockSize; (often 512 bytes) NB: BlockSize * TotalBlocks = disk space
   le64 TotalBlocks;  redundant with other infolevels but easy to ret here
   le64 BlocksAvail;  although redundant, easy to return
   le64 UserBlocksAvail;      bavail
   le64 TotalFileNodes;
   le64 FreeFileNodes;
   le64 FileSysIdentifier;    fsid
   (NB statfs field Namelen comes from FILE_SYSTEM_ATTRIBUTE_INFO call)
   (NB statfs field flags can come from FILE_SYSTEM_DEVICE_INFO call)
*/

#define SMB_QUERY_POSIX_WHO_AM_I  0x202 /* QFS Info */
/* returns:
        __u32 flags;  0 = Authenticated user 1 = GUEST
        __u32 mask;  which flags bits server understands ie 0x0001
        __u64 unix_user_id;
        __u64 unix_user_gid;
        __u32 number_of_supplementary_gids;  may be zero
        __u32 number_of_sids;  may be zero
        __u32 length_of_sid_array;  in bytes - may be zero
        __u32 pad;  reserved - MBZ
        __u64 gid_array[0];  may be empty
        __u8 * psid_list  may be empty
*/

/* ... more as we think of them :-). */

/* SMB POSIX ACL definitions. */
/* Wire format is (all little endian) :

[2 bytes]              -     Version number.
[2 bytes]              -     Number of ACE entries to follow.
[2 bytes]              -     Number of default ACE entries to follow.
-------------------------------------
^
|
ACE entries
|
v
-------------------------------------
^
|
Default ACE entries
|
v
-------------------------------------

Where an ACE entry looks like :

[1 byte]           - Entry type.

Entry types are :

ACL_USER_OBJ            0x01
ACL_USER                0x02
ACL_GROUP_OBJ           0x04
ACL_GROUP               0x08
ACL_MASK                0x10
ACL_OTHER               0x20

[1 byte]          - permissions (perm_t)

perm_t types are :

ACL_READ                0x04
ACL_WRITE               0x02
ACL_EXECUTE             0x01

[8 bytes]         - uid/gid to apply this permission to.

In the same format as the uid/gid fields in the other
UNIX extensions definitions. Use 0xFFFFFFFFFFFFFFFF for
the MASK and OTHER entry types.

If the Number of ACE entries for either file or default ACE's
is set to 0xFFFF this means ignore this kind of ACE (and the
number of entries sent will be zero.

*/

#define SMB_QUERY_POSIX_WHOAMI     0x202

enum smb_whoami_flags {
    SMB_WHOAMI_GUEST = 0x1 /* Logged in as (or squashed to) guest */
};

/* Mask of which WHOAMI bits are valid. This should make it easier for clients
 * to cope with servers that have different sets of WHOAMI flags (as more get
 * added).
 */
#define SMB_WHOAMI_MASK 0x00000001

/*
   SMBWhoami - Query the user mapping performed by the server for the
   connected tree. This is a subcommand of the TRANS2_QFSINFO.

   Returns:
	4 bytes unsigned -	mapping flags (smb_whoami_flags)
	4 bytes unsigned -	flags mask

	8 bytes unsigned -	primary UID
	8 bytes unsigned -	primary GID
	4 bytes unsigned -	number of supplementary GIDs
	4 bytes unsigned -	number of SIDs
	4 bytes unsigned -	SID list byte count
	4 bytes -		pad / reserved (must be zero)

	8 bytes unsigned[] -	list of GIDs (may be empty)
	struct dom_sid[] -		list of SIDs (may be empty)
*/

/*
 * The following trans2 is done between client and server
 * as a FSINFO call to set up the encryption state for transport
 * encryption.
 * This is a subcommand of the TRANS2_QFSINFO.
 *
 * The request looks like :
 *
 * [data block] -> SPNEGO framed GSSAPI request.
 *
 * The reply looks like :
 *
 * [data block] -> SPNEGO framed GSSAPI reply - if error
 *                 is NT_STATUS_OK then we're done, if it's
 *                 NT_STATUS_MORE_PROCESSING_REQUIRED then the
 *                 client needs to keep going. If it's an
 *                 error it can be any NT_STATUS error.
 *
 */

#define SMB_REQUEST_TRANSPORT_ENCRYPTION     0x203 /* QFSINFO */
#define SMB_ENCRYPTION_GSSAPI                0x8000

/* The query/set info levels for POSIX ACLs. */
#define SMB_QUERY_POSIX_ACL  0x204
#define SMB_SET_POSIX_ACL  0x204

/* Current on the wire ACL version. */
#define SMB_POSIX_ACL_VERSION 1

/* ACE entry type. */
#define SMB_POSIX_ACL_USER_OBJ            0x01
#define SMB_POSIX_ACL_USER                0x02
#define SMB_POSIX_ACL_GROUP_OBJ           0x04
#define SMB_POSIX_ACL_GROUP               0x08
#define SMB_POSIX_ACL_MASK                0x10
#define SMB_POSIX_ACL_OTHER               0x20

/* perm_t types. */
#define SMB_POSIX_ACL_READ                0x04
#define SMB_POSIX_ACL_WRITE               0x02
#define SMB_POSIX_ACL_EXECUTE             0x01

#define SMB_POSIX_ACL_HEADER_SIZE         6
#define SMB_POSIX_ACL_ENTRY_SIZE         10

#define SMB_POSIX_IGNORE_ACE_ENTRIES	0xFFFF

/* Definition of data block of SMB_SET_POSIX_LOCK */
/*
  [2 bytes] lock_type - 0 = Read, 1 = Write, 2 = Unlock
  [2 bytes] lock_flags - 1 = Wait (only valid for setlock)
  [4 bytes] pid = locking context.
  [8 bytes] start = unsigned 64 bits.
  [8 bytes] length = unsigned 64 bits.
*/

#define POSIX_LOCK_TYPE_OFFSET 0
#define POSIX_LOCK_FLAGS_OFFSET 2
#define POSIX_LOCK_PID_OFFSET 4
#define POSIX_LOCK_START_OFFSET 8
#define POSIX_LOCK_LEN_OFFSET 16
#define POSIX_LOCK_DATA_SIZE 24

#define POSIX_LOCK_FLAG_NOWAIT 0
#define POSIX_LOCK_FLAG_WAIT 1

#define POSIX_LOCK_TYPE_READ 0
#define POSIX_LOCK_TYPE_WRITE 1
#define POSIX_LOCK_TYPE_UNLOCK 2

/* SMB_POSIX_PATH_OPEN "open_mode" definitions. */
#define SMB_O_RDONLY			  0x1
#define SMB_O_WRONLY			  0x2
#define SMB_O_RDWR			  0x4

#define SMB_ACCMODE			  0x7

#define SMB_O_CREAT			 0x10
#define SMB_O_EXCL			 0x20
#define SMB_O_TRUNC			 0x40
#define SMB_O_APPEND			 0x80
#define SMB_O_SYNC			0x100
#define SMB_O_DIRECTORY			0x200
#define SMB_O_NOFOLLOW			0x400
#define SMB_O_DIRECT			0x800

/* Definition of request data block for SMB_POSIX_PATH_OPEN */
/*
  [4 bytes] flags (as smb_ntcreate_Flags).
  [4 bytes] open_mode			- SMB_O_xxx flags above.
  [8 bytes] mode_t (permissions)	- same encoding as "Standard UNIX permissions" above in SMB_SET_FILE_UNIX_BASIC.
  [2 bytes] ret_info_level	- optimization. Info level to be returned.
*/

/* Definition of reply data block for SMB_POSIX_PATH_OPEN */

#define SMB_NO_INFO_LEVEL_RETURNED 0xFFFF

/*
  [2 bytes] - flags field. Identical to flags reply for oplock response field in SMBNTCreateX)
  [2 bytes] - FID returned.
  [4 bytes] - CreateAction (same as in NTCreateX response).
  [2 bytes] - reply info level    - as requested or 0xFFFF if not available.
  [2 bytes] - padding (must be zero)
  [n bytes] - info level reply  - if available.
*/

/* Definition of request data block for SMB_POSIX_UNLINK */
/*
  [2 bytes] flags (defined below).
*/

#define SMB_POSIX_UNLINK_FILE_TARGET 0
#define SMB_POSIX_UNLINK_DIRECTORY_TARGET 1

#define INFO_LEVEL_IS_UNIX(level) ((((level) >= MIN_UNIX_INFO_LEVEL) && \
			((level) <= MAX_UNIX_INFO_LEVEL)) || \
			((level) == FSCC_FILE_POSIX_INFORMATION))

#endif /* __SMB_UNIX_EXT_H__ */
