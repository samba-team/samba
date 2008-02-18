/* 
   Unix SMB/CIFS implementation.
   SMB parameters and setup
   Copyright (C) Gerald (Jerry) Carter        2005
   
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

#ifndef _RPC_NTSVCS_H /* _RPC_NTSVCS_H */
#define _RPC_NTSVCS_H

/* ntsvcs pipe */

#define NTSVCS_GET_VERSION		0x02
#define NTSVCS_VALIDATE_DEVICE_INSTANCE	0x06
#define NTSVCS_GET_ROOT_DEVICE_INSTANCE	0x07
#define NTSVCS_GET_DEVICE_LIST		0x0a
#define NTSVCS_GET_DEVICE_LIST_SIZE	0x0b
#define NTSVCS_GET_DEVICE_REG_PROPERTY	0x0d
#define NTSVCS_HW_PROFILE_FLAGS		0x28
#define NTSVCS_GET_HW_PROFILE_INFO	0x29
#define NTSVCS_GET_VERSION_INTERNAL	0x3e


/**************************/

typedef struct {
	UNISTR2 *devicename;
	uint32 buffer_size;
	uint32 flags;
} NTSVCS_Q_GET_DEVICE_LIST;

typedef struct {
	UNISTR2 devicepath;
	uint32 needed;
	WERROR status;
} NTSVCS_R_GET_DEVICE_LIST;

/**************************/

typedef struct {
	UNISTR2 devicepath;
	uint32 property;
	uint32 unknown2;
	uint32 buffer_size1;
	uint32 buffer_size2;
	uint32 unknown5;
} NTSVCS_Q_GET_DEVICE_REG_PROPERTY;

typedef struct {
	uint32 unknown1;
	REGVAL_BUFFER value;
	uint32 size;
	uint32 needed;
	WERROR status;
} NTSVCS_R_GET_DEVICE_REG_PROPERTY;

#endif /* _RPC_NTSVCS_H */
