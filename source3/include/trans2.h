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

#ifndef _TRANS2_H_
#define _TRANS2_H_

/* Define the structures needed for the trans2 calls. */

/*******************************************************
 For DosFindFirst/DosFindNext - level 1

MAXFILENAMELEN = 255;
FDATE == uint16
FTIME == uint16
ULONG == uint32
USHORT == uint16

typedef struct _FILEFINDBUF {
Byte offset   Type     name                description
-------------+-------+-------------------+--------------
0             FDATE    fdateCreation;
2             FTIME    ftimeCreation;
4             FDATE    fdateLastAccess;
6             FTIME    ftimeLastAccess;
8             FDATE    fdateLastWrite;
10            FTIME    ftimeLastWrite;
12            ULONG    cbFile               file length in bytes
16            ULONG    cbFileAlloc          size of file allocation unit
20            USHORT   attrFile
22            UCHAR    cchName              length of name to follow (not including zero)
23            UCHAR    achName[MAXFILENAMELEN]; Null terminated name
} FILEFINDBUF;
*********************************************************/

#define l1_fdateCreation 0
#define l1_fdateLastAccess 4
#define l1_fdateLastWrite 8
#define l1_cbFile 12
#define l1_cbFileAlloc 16
#define l1_attrFile 20
#define l1_cchName 22
#define l1_achName 23

/**********************************************************
For DosFindFirst/DosFindNext - level 2

typedef struct _FILEFINDBUF2 {
Byte offset   Type     name                description
-------------+-------+-------------------+--------------
0             FDATE    fdateCreation;
2             FTIME    ftimeCreation;
4             FDATE    fdateLastAccess;
6             FTIME    ftimeLastAccess;
8             FDATE    fdateLastWrite;
10            FTIME    ftimeLastWrite;
12            ULONG    cbFile               file length in bytes
16            ULONG    cbFileAlloc          size of file allocation unit
20            USHORT   attrFile
22            ULONG    cbList               Extended attribute list (always 0)
26            UCHAR    cchName              length of name to follow (not including zero)
27            UCHAR    achName[MAXFILENAMELEN]; Null terminated name
} FILEFINDBUF2;
*************************************************************/

#define l2_fdateCreation 0
#define l2_fdateLastAccess 4
#define l2_fdateLastWrite 8
#define l2_cbFile 12
#define l2_cbFileAlloc 16
#define l2_attrFile 20
#define l2_cbList 22
#define l2_cchName 26
#define l2_achName 27


/**********************************************************
For DosFindFirst/DosFindNext - level 260

typedef struct _FILEFINDBUF260 {
Byte offset   Type     name                description
-------------+-------+-------------------+--------------
0              ULONG  NextEntryOffset;
4              ULONG  FileIndex;
8              LARGE_INTEGER CreationTime;
16             LARGE_INTEGER LastAccessTime;
24             LARGE_INTEGER LastWriteTime;
32             LARGE_INTEGER ChangeTime;
40             LARGE_INTEGER EndOfFile;
48             LARGE_INTEGER AllocationSize;
56             ULONG FileAttributes;
60             ULONG FileNameLength;
64             ULONG EaSize;
68             CHAR ShortNameLength;
70             UNICODE ShortName[12];
94             UNICODE FileName[];
*************************************************************/

#define l260_achName 94


/**********************************************************
For DosQueryPathInfo/DosQueryFileInfo/DosSetPathInfo/
DosSetFileInfo - level 1

typedef struct _FILESTATUS {
Byte offset   Type     name                description
-------------+-------+-------------------+--------------
0             FDATE    fdateCreation;
2             FTIME    ftimeCreation;
4             FDATE    fdateLastAccess;
6             FTIME    ftimeLastAccess;
8             FDATE    fdateLastWrite;
10            FTIME    ftimeLastWrite;
12            ULONG    cbFile               file length in bytes
16            ULONG    cbFileAlloc          size of file allocation unit
20            USHORT   attrFile
} FILESTATUS;
*************************************************************/

/* Use the l1_ defines from DosFindFirst */

/**********************************************************
For DosQueryPathInfo/DosQueryFileInfo/DosSetPathInfo/
DosSetFileInfo - level 2

typedef struct _FILESTATUS2 {
Byte offset   Type     name                description
-------------+-------+-------------------+--------------
0             FDATE    fdateCreation;
2             FTIME    ftimeCreation;
4             FDATE    fdateLastAccess;
6             FTIME    ftimeLastAccess;
8             FDATE    fdateLastWrite;
10            FTIME    ftimeLastWrite;
12            ULONG    cbFile               file length in bytes
16            ULONG    cbFileAlloc          size of file allocation unit
20            USHORT   attrFile
22            ULONG    cbList               Length of EA's (0)
} FILESTATUS2;
*************************************************************/

/* Use the l2_ #defines from DosFindFirst */

/**********************************************************
For DosQFSInfo/DosSetFSInfo - level 1

typedef struct _FSALLOCATE {
Byte offset   Type     name                description
-------------+-------+-------------------+--------------
0             ULONG    idFileSystem       id of file system
4             ULONG    cSectorUnit        number of sectors per allocation unit
8             ULONG    cUnit              number of allocation units
12            ULONG    cUnitAvail         Available allocation units
16            USHORT   cbSector           bytes per sector
} FSALLOCATE;
*************************************************************/

#define l1_idFileSystem 0
#define l1_cSectorUnit 4
#define l1_cUnit 8
#define l1_cUnitAvail 12
#define l1_cbSector 16

/**********************************************************
For DosQFSInfo/DosSetFSInfo - level 2

typedef struct _FSINFO {
Byte offset   Type     name                description
-------------+-------+-------------------+--------------
0             FDATE   vol_fdateCreation
2             FTIME   vol_ftimeCreation
4             UCHAR   vol_cch             length of volume name (excluding NULL)
5             UCHAR   vol_szVolLabel[12]  volume name
} FSINFO;
*************************************************************/

#define SMB_INFO_STANDARD               1  /* FILESTATUS3 struct */
#define SMB_INFO_SET_EA                 2  /* EAOP2 struct, only valid on set not query */
#define SMB_INFO_QUERY_EA_SIZE          2  /* FILESTATUS4 struct, only valid on query not set */
#define SMB_INFO_QUERY_EAS_FROM_LIST    3  /* only valid on query not set */
#define SMB_INFO_QUERY_ALL_EAS          4  /* only valid on query not set */
#define SMB_INFO_IS_NAME_VALID          6
#define SMB_INFO_STANDARD_LONG          11  /* similar to level 1, ie struct FileStatus3 */
#define SMB_QUERY_EA_SIZE_LONG          12  /* similar to level 2, ie struct FileStatus4 */
#define SMB_QUERY_FS_LABEL_INFO         0x101
#define SMB_QUERY_FS_VOLUME_INFO        0x102
#define SMB_QUERY_FS_SIZE_INFO          0x103
#define SMB_QUERY_FS_DEVICE_INFO        0x104
#define SMB_QUERY_FS_ATTRIBUTE_INFO     0x105
#if 0
#define SMB_QUERY_FS_QUOTA_INFO		
#endif

#define l2_vol_fdateCreation 0
#define l2_vol_cch 4
#define l2_vol_szVolLabel 5


#define SMB_QUERY_FILE_BASIC_INFO	0x101
#define SMB_QUERY_FILE_STANDARD_INFO	0x102
#define SMB_QUERY_FILE_EA_INFO		0x103
#define SMB_QUERY_FILE_NAME_INFO	0x104
#define SMB_QUERY_FILE_ALLOCATION_INFO	0x105
#define SMB_QUERY_FILE_END_OF_FILEINFO	0x106
#define SMB_QUERY_FILE_ALL_INFO		0x107
#define SMB_QUERY_FILE_ALT_NAME_INFO	0x108
#define SMB_QUERY_FILE_STREAM_INFO	0x109
#define SMB_QUERY_COMPRESSION_INFO	0x10b

#define SMB_FIND_INFO_STANDARD			1
#define SMB_FIND_EA_SIZE			2
#define SMB_FIND_EA_LIST			3
#define SMB_FIND_FILE_DIRECTORY_INFO		0x101
#define SMB_FIND_FILE_FULL_DIRECTORY_INFO	0x102
#define SMB_FIND_FILE_NAMES_INFO		0x103
#define SMB_FIND_FILE_BOTH_DIRECTORY_INFO	0x104
#define SMB_FIND_ID_FULL_DIRECTORY_INFO		0x105
#define SMB_FIND_ID_BOTH_DIRECTORY_INFO		0x106

#define SMB_SET_FILE_BASIC_INFO		0x101
#define SMB_SET_FILE_DISPOSITION_INFO	0x102
#define SMB_SET_FILE_ALLOCATION_INFO	0x103
#define SMB_SET_FILE_END_OF_FILE_INFO	0x104

/* Query FS info. */
#define SMB_INFO_ALLOCATION		1
#define SMB_INFO_VOLUME			2

/*
 * Thursby MAC extensions....
 */

/*
 * MAC CIFS Extensions have the range 0x300 - 0x2FF reserved.
 * Supposedly Microsoft have agreed to this.
 */

#define MIN_MAC_INFO_LEVEL 0x300
#define MAX_MAC_INFO_LEVEL 0x3FF

#define SMB_MAC_QUERY_FS_INFO           0x301

#define DIRLEN_GUESS (45+MAX(l1_achName,l2_achName))

/*
 * DeviceType and Characteristics returned in a
 * SMB_QUERY_FS_DEVICE_INFO call.
 */

#define DEVICETYPE_CD_ROM		0x2
#define DEVICETYPE_CD_ROM_FILE_SYSTEM	0x3
#define DEVICETYPE_DISK			0x7
#define DEVICETYPE_DISK_FILE_SYSTEM	0x8
#define DEVICETYPE_FILE_SYSTEM		0x9

/* Characteristics. */
#define TYPE_REMOVABLE_MEDIA		0x1
#define TYPE_READ_ONLY_DEVICE		0x2
#define TYPE_FLOPPY			0x4
#define TYPE_WORM			0x8
#define TYPE_REMOTE			0x10
#define TYPE_MOUNTED			0x20
#define TYPE_VIRTUAL			0x40

/* SMB_FS_SECTOR_SIZE_INFORMATION values */
#define SSINFO_FLAGS_ALIGNED_DEVICE			0x00000001
#define SSINFO_FLAGS_PARTITION_ALIGNED_ON_DEVICE	0x00000002
#define SSINFO_FLAGS_NO_SEEK_PENALTY			0x00000004
#define SSINFO_FLAGS_TRIM_ENABLED			0x00000008

#define SSINFO_OFFSET_UNKNOWN				0xffffffff

/* NT passthrough levels... */

#define SMB_FILE_DIRECTORY_INFORMATION			1001
#define SMB_FILE_FULL_DIRECTORY_INFORMATION		1002
#define SMB_FILE_BOTH_DIRECTORY_INFORMATION		1003
#define SMB_FILE_BASIC_INFORMATION			1004
#define SMB_FILE_STANDARD_INFORMATION			1005
#define SMB_FILE_INTERNAL_INFORMATION			1006
#define SMB_FILE_EA_INFORMATION				1007
#define SMB_FILE_ACCESS_INFORMATION			1008
#define SMB_FILE_NAME_INFORMATION			1009
#define SMB_FILE_RENAME_INFORMATION			1010
#define SMB2_FILE_RENAME_INFORMATION_INTERNAL		0xFF0A	/* Internal mapped version. */
#define SMB_FILE_LINK_INFORMATION			1011
#define SMB_FILE_NAMES_INFORMATION			1012
#define SMB_FILE_DISPOSITION_INFORMATION		1013
#define SMB_FILE_POSITION_INFORMATION			1014
#define SMB_FILE_FULL_EA_INFORMATION			1015
#define SMB_FILE_MODE_INFORMATION			1016
#define SMB_FILE_ALIGNMENT_INFORMATION			1017
#define SMB_FILE_ALL_INFORMATION			1018
#define SMB_FILE_ALLOCATION_INFORMATION			1019
#define SMB_FILE_END_OF_FILE_INFORMATION		1020
#define SMB_FILE_ALTERNATE_NAME_INFORMATION		1021
#define SMB_FILE_STREAM_INFORMATION			1022
#define SMB_FILE_PIPE_INFORMATION			1023
#define SMB_FILE_PIPE_LOCAL_INFORMATION			1024
#define SMB_FILE_PIPE_REMOTE_INFORMATION		1025
#define SMB_FILE_MAILSLOT_QUERY_INFORMATION		1026
#define SMB_FILE_MAILSLOT_SET_INFORMATION		1027
#define SMB_FILE_COMPRESSION_INFORMATION		1028
#define SMB_FILE_OBJECTID_INFORMATION			1029
#define SMB_FILE_COMPLETION_INFORMATION			1030
#define SMB_FILE_MOVE_CLUSTER_INFORMATION		1031
#define SMB_FILE_QUOTA_INFORMATION			1032
#define SMB_FILE_REPARSEPOINT_INFORMATION		1033
#define SMB_FILE_NETWORK_OPEN_INFORMATION		1034
#define SMB_FILE_ATTRIBUTE_TAG_INFORMATION		1035
#define SMB_FILE_TRACKING_INFORMATION			1036
#define SMB_FILE_ID_BOTH_DIRECTORY_INFORMATION		1037
#define SMB_FILE_ID_FULL_DIRECTORY_INFORMATION		1038
#define SMB_FILE_VALID_DATA_LENGTH_INFORMATION		1039
#define SMB_FILE_SHORT_NAME_INFORMATION			1040
#define SMB_FILE_SFIO_RESERVE_INFORMATION		1044
#define SMB_FILE_SFIO_VOLUME_INFORMATION		1045
#define SMB_FILE_HARD_LINK_INFORMATION			1046
#define SMB_FILE_NORMALIZED_NAME_INFORMATION		1048
#define SMB_FILE_ID_GLOBAL_TX_DIRECTORY_INFORMATION	1050
#define SMB_FILE_STANDARD_LINK_INFORMATION		1054
#define SMB_FILE_MAXIMUM_INFORMATION			1055

/* NT passthough levels for qfsinfo. */

#define SMB_FS_VOLUME_INFORMATION			1001
#define SMB_FS_LABEL_INFORMATION			1002
#define SMB_FS_SIZE_INFORMATION				1003
#define SMB_FS_DEVICE_INFORMATION			1004
#define SMB_FS_ATTRIBUTE_INFORMATION			1005
#define SMB_FS_QUOTA_INFORMATION			1006
#define SMB_FS_FULL_SIZE_INFORMATION			1007
#define SMB_FS_OBJECTID_INFORMATION			1008
#define SMB_FS_SECTOR_SIZE_INFORMATION			1011

/* SMB_FS_DEVICE_INFORMATION device types. */
#define FILE_DEVICE_CD_ROM		0x2
#define FILE_DEVICE_DISK		0x7

/* SMB_FS_DEVICE_INFORMATION characteristics. */
#define FILE_REMOVABLE_MEDIA		0x001
#define FILE_READ_ONLY_DEVICE		0x002
#define FILE_FLOPPY_DISKETTE		0x004
#define FILE_WRITE_ONCE_MEDIA		0x008
#define FILE_REMOTE_DEVICE		0x010
#define FILE_DEVICE_IS_MOUNTED		0x020
#define FILE_VIRTUAL_VOLUME		0x040
#define FILE_DEVICE_SECURE_OPEN		0x100

/* flags on trans2 findfirst/findnext that control search */
#define FLAG_TRANS2_FIND_CLOSE          0x1
#define FLAG_TRANS2_FIND_CLOSE_IF_END   0x2
#define FLAG_TRANS2_FIND_REQUIRE_RESUME 0x4
#define FLAG_TRANS2_FIND_CONTINUE       0x8
#define FLAG_TRANS2_FIND_BACKUP_INTENT  0x10

#endif
