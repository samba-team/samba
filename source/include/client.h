/*
   Unix SMB/CIFS implementation.
   SMB parameters and setup
   Copyright (C) Andrew Tridgell 1992-1998
   Copyright (C) Luke Kenneth Casson Leighton 1996-1998
   Copyright (C) Jeremy Allison 1998
   Copyright (C) James Myers 2003 <myersjj@samba.org>

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

#ifndef _CLIENT_H
#define _CLIENT_H

/* the client asks for a smaller buffer to save ram and also to get more
   overlap on the wire. This size gives us a nice read/write size, which
   will be a multiple of the page size on almost any system */
#define CLI_BUFFER_SIZE (0xFFFF)
#define SMBCLI_DFS_MAX_REFERRAL_LEVEL 3

#define SAFETY_MARGIN 1024
#define LARGE_WRITEX_HDR_SIZE 65


/*
 * These definitions depend on smb.h
 */

struct file_info
{
	uint64_t size;
	uint16_t mode;
	uid_t uid;
	gid_t gid;
	/* these times are normally kept in GMT */
	time_t mtime;
	time_t atime;
	time_t ctime;
	const char *name;
	char short_name[13*3]; /* the *3 is to cope with multi-byte */
};

struct print_job_info
{
	uint16_t id;
	uint16_t priority;
	size_t size;
	fstring user;
	fstring name;
	time_t t;
};

typedef struct referral_info
{
	int server_type;
	int referral_flags;
	int proximity;
	int ttl;
	int pathOffset;
	int altPathOffset;
	int nodeOffset;
	char *path;
	char *altPath;
	char *node;
	char *host;
	char *share;
} referral_info;

typedef struct dfs_info
{
	int path_consumed;
	int referral_flags;
	int selected_referral;
	int number_referrals;
	referral_info referrals[10];
} dfs_info;

/* Internal client error codes for smbcli_request_context.internal_error_code */
#define SMBCLI_ERR_INVALID_TRANS_RESPONSE		100

#define DFS_MAX_CLUSTER_SIZE 8
/* client_context: used by cliraw callers to maintain Dfs
 * state across multiple Dfs servers
 */
struct cli_client
{
	const char* sockops;
	char* username;
	char* password;
	char* workgroup;
	TALLOC_CTX *mem_ctx;
	int number_members;
	BOOL use_dfs;				/* True if client should support Dfs */
	int connection_flags;		/* see CLI_FULL_CONN.. below */
	uint16_t max_xmit_frag;
	uint16_t max_recv_frag;
	struct smbcli_state *cli[DFS_MAX_CLUSTER_SIZE];
};

#define SMBCLI_FULL_CONNECTION_DONT_SPNEGO 0x0001
#define SMBCLI_FULL_CONNECTION_USE_KERBEROS 0x0002
#define SMBCLI_FULL_CONNECTION_ANNONYMOUS_FALLBACK 0x0004
#define SMBCLI_FULL_CONNECTION_USE_DFS 0x0008

#endif /* _CLIENT_H */
