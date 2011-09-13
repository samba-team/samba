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

#define CLI_BUFFER_SIZE (0xFFFF)

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

struct cli_state {
	/**
	 * A list of subsidiary connections for DFS.
	 */
        struct cli_state *prev, *next;
	int rap_error;
	NTSTATUS raw_status; /* maybe via NT_STATUS_DOS() */

	/* The credentials used to open the cli_state connection. */
	char *domain;
	char *user_name;
	char *password; /* Can be null to force use of zero NTLMSSP session key. */

	/*
	 * The following strings are the
	 * ones returned by the server if
	 * the protocol > NT1.
	 */
	char *server_type;
	char *server_os;
	char *server_domain;

	char *share;
	char *dev;

	DATA_BLOB secblob; /* cryptkey or negTokenInit */
	uint32 sesskey;
	int serverzone;
	uint32 servertime;
	int timeout; /* in milliseconds. */
	int initialised;
	int win95;
	bool is_guestlogin;
	/* What the server offered. */
	uint32_t server_posix_capabilities;
	/* What the client requested. */
	uint32_t requested_posix_capabilities;
	bool dfsroot;

	struct smb_signing_state *signing_state;

	struct smb_trans_enc_state *trans_enc_state; /* Setup if we're encrypting SMB's. */

	/* the session key for this CLI, outside
	   any per-pipe authenticaion */
	DATA_BLOB user_session_key;

	/* The list of pipes currently open on this connection. */
	struct rpc_pipe_client *pipe_list;

	bool use_kerberos;
	bool fallback_after_kerberos;
	bool use_ccache;
	bool got_kerberos_mechanism; /* Server supports krb5 in SPNEGO. */

	bool use_oplocks; /* should we use oplocks? */

	bool case_sensitive; /* False by default. */

	/* Where (if anywhere) this is mounted under DFS. */
	char *dfs_mountpoint;

	struct {
		int fd;
		struct sockaddr_storage local_ss;
		struct sockaddr_storage remote_ss;
		const char *remote_name;
		const char *remote_realm;
		struct tevent_req *read_smb_req;
		struct tevent_queue *outgoing;
		struct tevent_req **pending;
		/*
		 * The incoming dispatch function should return:
		 * - NT_STATUS_RETRY, if more incoming PDUs are expected.
		 * - NT_STATUS_OK, if no more processing is desired, e.g.
		 *                 the dispatch function called
		 *                 tevent_req_done().
		 * - All other return values disconnect the connection.
		 */
		NTSTATUS (*dispatch_incoming)(struct cli_state *cli,
					      TALLOC_CTX *frame,
					      uint8_t *inbuf);

		enum protocol_types protocol;

		struct {
			struct {
				uint32_t capabilities;
				uint32_t max_xmit;
			} client;

			struct {
				uint32_t capabilities;
				uint32_t max_xmit;
				uint16_t max_mux;
				uint16_t security_mode;
				bool readbraw;
				bool writebraw;
				bool lockread;
				bool writeunlock;
			} server;

			uint32_t capabilities;
			uint32_t max_xmit;

			uint16_t mid;
		} smb1;
	} conn;

	struct {
		uint16_t pid;
		uint16_t vc_num;
		uint16_t tid;
		uint16_t uid;
	} smb1;

	struct {
		uint64_t mid;
		uint32_t pid;
		uint32_t tid;
		uint64_t uid;

		/* SMB2 negprot */
		uint16_t security_mode;
		uint16_t dialect_revision;
		struct GUID server_guid;
		uint32_t server_capabilities;
		uint32_t max_transact_size;
		uint32_t max_read_size;
		uint32_t max_write_size;
		struct timespec system_time;
		struct timespec server_start_time;
		DATA_BLOB gss_blob;

		/* SMB2 tcon */
		uint8_t share_type;
		uint32_t share_flags;
		uint32_t share_capabilities;
		uint32_t maximal_access;
	} smb2;
};

struct file_info {
	uint64_t size;
	uint16 mode;
	uid_t uid;
	gid_t gid;
	/* these times are normally kept in GMT */
	struct timespec mtime_ts;
	struct timespec atime_ts;
	struct timespec ctime_ts;
	char *name;
	char *short_name;
};

#define CLI_FULL_CONNECTION_DONT_SPNEGO 0x0001
#define CLI_FULL_CONNECTION_USE_KERBEROS 0x0002
#define CLI_FULL_CONNECTION_ANONYMOUS_FALLBACK 0x0004
#define CLI_FULL_CONNECTION_FALLBACK_AFTER_KERBEROS 0x0008
#define CLI_FULL_CONNECTION_OPLOCKS 0x0010
#define CLI_FULL_CONNECTION_LEVEL_II_OPLOCKS 0x0020
#define CLI_FULL_CONNECTION_USE_CCACHE 0x0040
#define CLI_FULL_CONNECTION_FORCE_DOS_ERRORS 0x0080
#define CLI_FULL_CONNECTION_FORCE_ASCII 0x0100

#endif /* _CLIENT_H */
