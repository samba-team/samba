/*
   Unix SMB/CIFS implementation.

   SMB2 create context specifc stuff

   Copyright (C) Ralph Boehme 2014

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

#ifndef __LIBCLI_SMB2_CREATE_CTX_H__
#define __LIBCLI_SMB2_CREATE_CTX_H__

/* http://opensource.apple.com/source/smb/smb-697.1.1/kernel/netsmb/smb_2.h */

/* "AAPL" Context Command Codes */
#define SMB2_CRTCTX_AAPL_SERVER_QUERY 1
#define SMB2_CRTCTX_AAPL_RESOLVE_ID   2

/* "AAPL" Server Query request/response bitmap */
#define SMB2_CRTCTX_AAPL_SERVER_CAPS 1
#define SMB2_CRTCTX_AAPL_VOLUME_CAPS 2
#define SMB2_CRTCTX_AAPL_MODEL_INFO  4

/* "AAPL" Client/Server Capabilities bitmap */
#define SMB2_CRTCTX_AAPL_SUPPORTS_READ_DIR_ATTR 1
#define SMB2_CRTCTX_AAPL_SUPPORTS_OSX_COPYFILE  2
#define SMB2_CRTCTX_AAPL_UNIX_BASED             4
#define SMB2_CRTCTX_AAPL_SUPPORTS_NFS_ACE       8

/* "AAPL" Volume Capabilities bitmap */
#define SMB2_CRTCTX_AAPL_SUPPORT_RESOLVE_ID 1
#define SMB2_CRTCTX_AAPL_CASE_SENSITIVE     2

#endif
