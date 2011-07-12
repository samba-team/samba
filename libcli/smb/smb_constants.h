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

/* protocol types. It assumes that higher protocols include lower protocols
   as subsets. */
enum protocol_types {
	PROTOCOL_NONE,
	PROTOCOL_CORE,
	PROTOCOL_COREPLUS,
	PROTOCOL_LANMAN1,
	PROTOCOL_LANMAN2,
	PROTOCOL_NT1,
	PROTOCOL_SMB2_02
};
#define PROTOCOL_SMB2 PROTOCOL_SMB2_02

/* NT Flags2 bits - cifs6.txt section 3.1.2 */
#define FLAGS2_LONG_PATH_COMPONENTS    0x0001
#define FLAGS2_EXTENDED_ATTRIBUTES     0x0002
#define FLAGS2_SMB_SECURITY_SIGNATURES 0x0004
#define FLAGS2_UNKNOWN_BIT4            0x0010
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

#endif /* _SMB_CONSTANTS_H */
