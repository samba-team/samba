/*
   Unix SMB/Netbios implementation.
   Version 1.9.
   SMB parameters and setup
   Copyright (C) Andrew Tridgell 1992-1998
   Copyright (C) Luke Kenneth Casson Leighton 1996-1998
   Copyright (C) Jeremy Allison 1998

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
#define CLI_BUFFER_SIZE (0x4400)

/*
 * These definitions depend on smb.h
 */

typedef struct file_info
{
	SMB_OFF_T size;
	uint16 mode;
	uid_t uid;
	gid_t gid;
	/* these times are normally kept in GMT */
	time_t mtime;
	time_t atime;
	time_t ctime;
	pstring name;
} file_info;

struct print_job_info
{
	uint16 id;
	uint16 priority;
	size_t size;
	fstring user;
	fstring name;
	time_t t;
};

struct cli_state
{
	int port;
	int fd;
	uint16 cnum;
	uint16 pid;
	uint16 mid;
	uint16 vuid;
	int protocol;
	int sec_mode;
	int rap_error;
	int privileges;

	struct ntuser_creds usr;
	BOOL retry;

	fstring eff_name;
	fstring desthost;

	/*
	 * The following strings are the
	 * ones returned by the server if
	 * the protocol > NT1.
	 */
	fstring server_type;
	fstring server_os;
	fstring server_domain;

	fstring share;
	fstring dev;
	struct nmb_name called;
	struct nmb_name calling;
	struct in_addr dest_ip;

	unsigned char cryptkey[8];
	unsigned char lm_cli_chal[8];
	unsigned char nt_cli_chal[128];
	size_t nt_cli_chal_len;

	BOOL use_ntlmv2;
	BOOL redirect;
	BOOL reuse;

	uint32 sesskey;
	int serverzone;
	uint32 servertime;
	int readbraw_supported;
	int writebraw_supported;
	int timeout;
	int max_xmit;
	int max_mux;
	char *outbuf;
	char *inbuf;
	int bufsize;
	int initialised;
	int win95;
	uint32 capabilities;

	/*
	 * Only used in NT domain calls.
	 */

	uint32 nt_error;                   /* NT RPC error code. */
	unsigned char sess_key[16];        /* Current session key. */
	unsigned char ntlmssp_hash[258];   /* ntlmssp data. */
	uint32 ntlmssp_cli_flgs;           /* ntlmssp client flags */
	uint32 ntlmssp_srv_flgs;           /* ntlmssp server flags */
	uint32 ntlmssp_seq_num;            /* ntlmssp sequence number */
	DOM_CRED clnt_cred;                /* Client credential. */
	uint16 max_xmit_frag;
	uint16 max_recv_frag;
};

struct cli_connection;

#endif /* _CLIENT_H */
