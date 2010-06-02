/* 
   Unix SMB/CIFS implementation.
   SMB parameters and setup
   Copyright (C) Andrew Tridgell              1992-2000
   Copyright (C) Luke Kenneth Casson Leighton 1996-2000
   
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

#ifndef _RPC_SECDES_H /* _RPC_SECDES_H */
#define _RPC_SECDES_H 

/* for ADS */
#define SEC_RIGHTS_FULL_CTRL		0xf01ff

/* A type to describe the mapping of generic access rights to object
   specific access rights. */

struct generic_mapping {
	uint32 generic_read;
	uint32 generic_write;
	uint32 generic_execute;
	uint32 generic_all;
};

struct standard_mapping {
	uint32 std_read;
	uint32 std_write;
	uint32 std_execute;
	uint32 std_all;
};

/* Standard access rights. */

#define STD_RIGHT_DELETE_ACCESS		0x00010000
#define STD_RIGHT_READ_CONTROL_ACCESS	0x00020000
#define STD_RIGHT_WRITE_DAC_ACCESS	0x00040000
#define STD_RIGHT_WRITE_OWNER_ACCESS	0x00080000
#define STD_RIGHT_SYNCHRONIZE_ACCESS	0x00100000

#define STD_RIGHT_ALL_ACCESS		0x001F0000

#endif /* _RPC_SECDES_H */
