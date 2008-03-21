/*
   Unix SMB/CIFS implementation.
   SMB parameters and setup
   Copyright (C) Andrew Tridgell 1992-1997
   Copyright (C) Luke Kenneth Casson Leighton 1996-1997
   Copyright (C) Paul Ashton 1997
   Copyright (C) Nigel Williams 2001
   Copyright (C) Gerald (Jerry) Carter 2006.

   
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

#ifndef _RPC_SRVSVC_H /* _RPC_SRVSVC_H */
#define _RPC_SRVSVC_H 

/* srvsvc pipe */
#define SRV_NET_CONN_ENUM          0x08
#define SRV_NET_FILE_ENUM          0x09
#define SRV_NET_FILE_CLOSE         0x0b
#define SRV_NET_SESS_ENUM          0x0c
#define SRV_NET_SESS_DEL           0x0d
#define SRV_NET_SHARE_ADD          0x0e
#define SRV_NET_SHARE_ENUM_ALL     0x0f
#define SRV_NET_SHARE_GET_INFO     0x10
#define SRV_NET_SHARE_SET_INFO     0x11
#define SRV_NET_SHARE_DEL          0x12
#define SRV_NET_SHARE_DEL_STICKY   0x13
#define SRV_NET_SRV_GET_INFO       0x15
#define SRV_NET_SRV_SET_INFO       0x16
#define SRV_NET_DISK_ENUM          0x17
#define SRV_NET_REMOTE_TOD         0x1c
#define SRV_NET_NAME_VALIDATE      0x21
#define SRV_NET_SHARE_ENUM         0x24
#define SRV_NET_FILE_QUERY_SECDESC 0x27
#define SRV_NET_FILE_SET_SECDESC   0x28


/***************************/

#endif /* _RPC_SRVSVC_H */
