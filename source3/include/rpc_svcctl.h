/* 
   Unix SMB/CIFS implementation.
   SMB parameters and setup
   Copyright (C) Andrew Tridgell              1992-1997,
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

#ifndef _RPC_SVCCTL_H /* _RPC_SVCCTL_H */
#define _RPC_SVCCTL_H 

/* svcctl pipe */

#define SVCCTL_CLOSE_SERVICE			0x00
#define SVCCTL_CONTROL_SERVICE			0x01
#define SVCCTL_LOCK_SERVICE_DB			0x03
#define SVCCTL_QUERY_SERVICE_SEC		0x04
#define SVCCTL_SET_SERVICE_SEC			0x05
#define SVCCTL_QUERY_STATUS			0x06
#define SVCCTL_UNLOCK_SERVICE_DB		0x08
#define SVCCTL_ENUM_DEPENDENT_SERVICES_W	0x0d
#define SVCCTL_ENUM_SERVICES_STATUS_W		0x0e
#define SVCCTL_OPEN_SCMANAGER_W			0x0f
#define SVCCTL_OPEN_SERVICE_W			0x10
#define SVCCTL_QUERY_SERVICE_CONFIG_W		0x11
#define SVCCTL_START_SERVICE_W			0x13
#define SVCCTL_GET_DISPLAY_NAME			0x14
#define SVCCTL_QUERY_SERVICE_CONFIG2_W		0x27
#define SVCCTL_QUERY_SERVICE_STATUSEX_W         0x28

/* ANSI versions not implemented currently 
#define SVCCTL_ENUM_SERVICES_STATUS_A		0x0e
#define SVCCTL_OPEN_SCMANAGER_A			0x1b
*/

#endif /* _RPC_SVCCTL_H */

