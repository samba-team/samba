/*
   Unix SMB/CIFS implementation.
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
#define CLI_BUFFER_SIZE (0xFFFF)


/*
 * These definitions depend on smb.h
 */

typedef struct file_info
{
	SMB_BIG_UINT size;
	uint16 mode;
	uid_t uid;
	gid_t gid;
	/* these times are normally kept in GMT */
	time_t mtime;
	time_t atime;
	time_t ctime;
	pstring name;
	char short_name[13*3]; /* the *3 is to cope with multi-byte */
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

typedef struct smb_sign_info {
	BOOL use_smb_signing;
	BOOL negotiated_smb_signing;
	BOOL temp_smb_signing;
	size_t mac_key_len;
	uint8 mac_key[64];
	uint32 send_seq_num;
	uint32 reply_seq_num;
	BOOL allow_smb_signing;
} smb_sign_info;

struct cli_state {
	int port;
	int fd;
	int smb_rw_error; /* Copy of last read or write error. */
	uint16 cnum;
	uint16 pid;
	uint16 mid;
	uint16 vuid;
	int protocol;
	int sec_mode;
	int rap_error;
	int privileges;

	fstring desthost;
	fstring user_name;
	fstring domain;

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
	fstring full_dest_host_name;
	struct in_addr dest_ip;

	struct pwd_info pwd;
	DATA_BLOB secblob; /* cryptkey or negTokenInit */
	uint32 sesskey;
	int serverzone;
	uint32 servertime;
	int readbraw_supported;
	int writebraw_supported;
	int timeout; /* in milliseconds. */
	int max_xmit;
	int max_mux;
	char *outbuf;
	char *inbuf;
	int bufsize;
	int initialised;
	int win95;
	uint32 capabilities;

	TALLOC_CTX *mem_ctx;

	smb_sign_info sign_info;

	/* the session key for this CLI, outside 
	   any per-pipe authenticaion */
	unsigned char user_session_key[16];

	/*
	 * Only used in NT domain calls.
	 */

	uint16 nt_pipe_fnum;               /* Pipe handle. */
	unsigned char sess_key[16];        /* Current session key. */
	unsigned char ntlmssp_hash[258];   /* ntlmssp data. */
	uint32 ntlmssp_cli_flgs;           /* ntlmssp client flags */
	uint32 ntlmssp_srv_flgs;           /* ntlmssp server flags */
	uint32 ntlmssp_seq_num;            /* ntlmssp sequence number */
	DOM_CRED clnt_cred;                /* Client credential. */
	fstring mach_acct;                 /* MYNAME$. */
	fstring srv_name_slash;            /* \\remote server. */
	fstring clnt_name_slash;           /* \\local client. */
	uint16 max_xmit_frag;
	uint16 max_recv_frag;
	uint32 ntlmssp_flags;
	BOOL use_kerberos;
	BOOL use_spnego;

	BOOL use_oplocks; /* should we use oplocks? */
	BOOL use_level_II_oplocks; /* should we use level II oplocks? */

	/* a oplock break request handler */
	BOOL (*oplock_handler)(struct cli_state *cli, int fnum, unsigned char level);

	BOOL force_dos_errors;

	/* was this structure allocated by cli_initialise? If so, then
           free in cli_shutdown() */
	BOOL allocated;

	/* Name of the pipe we're talking to, if any */
	fstring pipe_name;
};

#define CLI_FULL_CONNECTION_DONT_SPNEGO 0x0001
#define CLI_FULL_CONNECTION_USE_KERBEROS 0x0002
#define CLI_FULL_CONNECTION_ANNONYMOUS_FALLBACK 0x0004

#endif /* _CLIENT_H */
