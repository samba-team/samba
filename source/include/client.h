/*
   Unix SMB/CIFS implementation.
   SMB parameters and setup
   Copyright (C) Andrew Tridgell 1992-1998
   Copyright (C) Luke Kenneth Casson Leighton 1996-1998
   Copyright (C) Jeremy Allison 1998

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

#ifndef _CLIENT_H
#define _CLIENT_H

/* the client asks for a smaller buffer to save ram and also to get more
   overlap on the wire. This size gives us a nice read/write size, which
   will be a multiple of the page size on almost any system */
#define CLI_BUFFER_SIZE (0xFFFF)
#define CLI_SAMBA_MAX_LARGE_READX_SIZE (127*1024) /* Works for Samba servers */
#define CLI_SAMBA_MAX_LARGE_WRITEX_SIZE (127*1024) /* Works for Samba servers */
#define CLI_WINDOWS_MAX_LARGE_READX_SIZE ((64*1024)-2) /* Windows servers are broken.... */
#define CLI_WINDOWS_MAX_LARGE_WRITEX_SIZE ((64*1024)-2) /* Windows servers are broken.... */
#define CLI_SAMBA_MAX_POSIX_LARGE_READX_SIZE (0xFFFF00) /* 24-bit len. */
#define CLI_SAMBA_MAX_POSIX_LARGE_WRITEX_SIZE (0xFFFF00) /* 24-bit len. */

/*
 * These definitions depend on smb.h
 */

struct print_job_info {
	uint16 id;
	uint16 priority;
	size_t size;
	fstring user;
	fstring name;
	time_t t;
};

struct cli_pipe_auth_data {
	enum pipe_auth_type auth_type; /* switch for the union below. Defined in ntdomain.h */
	enum pipe_auth_level auth_level; /* defined in ntdomain.h */

	char *domain;
	char *user_name;

	union {
		struct schannel_auth_struct *schannel_auth;
		NTLMSSP_STATE *ntlmssp_state;
		struct kerberos_auth_struct *kerberos_auth;
	} a_u;
};

struct rpc_pipe_client {
	struct rpc_pipe_client *prev, *next;

	enum dcerpc_transport_t transport_type;

	union {
		struct {
			struct cli_state *cli;
			const char *pipe_name;
			uint16 fnum;
		} np;
		struct {
			int fd;
		} sock;
	} trans ;

	struct ndr_syntax_id abstract_syntax;
	struct ndr_syntax_id transfer_syntax;

	char *desthost;
	char *srv_name_slash;

	uint16 max_xmit_frag;
	uint16 max_recv_frag;

	struct cli_pipe_auth_data *auth;

	/* The following is only non-null on a netlogon pipe. */
	struct dcinfo *dc;
};

/* Transport encryption state. */
enum smb_trans_enc_type {
		SMB_TRANS_ENC_NTLM
#if defined(HAVE_GSSAPI) && defined(HAVE_KRB5)
		, SMB_TRANS_ENC_GSS
#endif
};

#if defined(HAVE_GSSAPI) && defined(HAVE_KRB5)
struct smb_tran_enc_state_gss {
        gss_ctx_id_t gss_ctx;
        gss_cred_id_t creds;
};
#endif

struct smb_trans_enc_state {
        enum smb_trans_enc_type smb_enc_type;
        uint16 enc_ctx_num;
        bool enc_on;
        union {
                NTLMSSP_STATE *ntlmssp_state;
#if defined(HAVE_GSSAPI) && defined(HAVE_KRB5)
                struct smb_tran_enc_state_gss *gss_state;
#endif
        } s;
};

struct cli_state {
	int port;
	int fd;
	/* Last read or write error. */
	enum smb_read_errors smb_rw_error;
	uint16 cnum;
	uint16 pid;
	uint16 mid;
	uint16 vuid;
	int protocol;
	int sec_mode;
	int rap_error;
	int privileges;

	fstring desthost;

	/* The credentials used to open the cli_state connection. */
	fstring domain;
	fstring user_name;
	struct pwd_info pwd;

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
	struct sockaddr_storage dest_ss;

	DATA_BLOB secblob; /* cryptkey or negTokenInit */
	uint32 sesskey;
	int serverzone;
	uint32 servertime;
	int readbraw_supported;
	int writebraw_supported;
	int timeout; /* in milliseconds. */
	size_t max_xmit;
	size_t max_mux;
	char *outbuf;
	char *inbuf;
	unsigned int bufsize;
	int initialised;
	int win95;
	bool is_samba;
	uint32 capabilities;
	uint32 posix_capabilities;
	bool dfsroot;

#if 0
	TALLOC_CTX *longterm_mem_ctx;
	TALLOC_CTX *call_mem_ctx;
#endif

	smb_sign_info sign_info;

	struct smb_trans_enc_state *trans_enc_state; /* Setup if we're encrypting SMB's. */

	/* the session key for this CLI, outside
	   any per-pipe authenticaion */
	DATA_BLOB user_session_key;

	/* The list of pipes currently open on this connection. */
	struct rpc_pipe_client *pipe_list;

	bool use_kerberos;
	bool fallback_after_kerberos;
	bool use_spnego;
	bool got_kerberos_mechanism; /* Server supports krb5 in SPNEGO. */

	bool use_oplocks; /* should we use oplocks? */
	bool use_level_II_oplocks; /* should we use level II oplocks? */

	/* a oplock break request handler */
	bool (*oplock_handler)(struct cli_state *cli, int fnum, unsigned char level);

	bool force_dos_errors;
	bool case_sensitive; /* False by default. */

	struct event_context *event_ctx;
	struct fd_event *fd_event;
	char *evt_inbuf;

	struct cli_request *outstanding_requests;
};

struct cli_request {
	struct cli_request *prev, *next;
	struct async_req *async;

	struct cli_state *cli;

	struct smb_trans_enc_state *enc_state;

	uint16_t mid;

	char *outbuf;
	size_t sent;
	char *inbuf;

	union {
		struct {
			off_t ofs;
			size_t size;
			ssize_t received;
			uint8_t *rcvbuf;
		} read;
	} data;
};

typedef struct file_info {
	struct cli_state *cli;
	SMB_BIG_UINT size;
	uint16 mode;
	uid_t uid;
	gid_t gid;
	/* these times are normally kept in GMT */
	struct timespec mtime_ts;
	struct timespec atime_ts;
	struct timespec ctime_ts;
	char *name;
	char short_name[13*3]; /* the *3 is to cope with multi-byte */
} file_info;

#define CLI_FULL_CONNECTION_DONT_SPNEGO 0x0001
#define CLI_FULL_CONNECTION_USE_KERBEROS 0x0002
#define CLI_FULL_CONNECTION_ANONYMOUS_FALLBACK 0x0004
#define CLI_FULL_CONNECTION_FALLBACK_AFTER_KERBEROS 0x0008

#endif /* _CLIENT_H */
