/* 
   Unix SMB/Netbios implementation.
   Version 2.0
   SMB wrapper functions - definitions
   Copyright (C) Andrew Tridgell 1998
   
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

#define SMBW_PREFIX "/smb/"

#define SMBW_FD_OFFSET 700
#define SMBW_CLI_FD 512
#define SMBW_MAX_OPEN 2048

#define SMBW_FILE_MODE (S_IFREG | 0644)
#define SMBW_DIR_MODE (S_IFDIR | 0755)

#define SMBW_PWD_ENV "PWD"
