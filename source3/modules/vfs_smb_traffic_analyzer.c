/*
 * traffic-analyzer VFS module. Measure the smb traffic users create
 * on the net.
 *
 * Copyright (C) Holger Hetterich, 2008
 * Copyright (C) Jeremy Allison, 2008
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"
#include "../lib/crypto/crypto.h"
#include "vfs_smb_traffic_analyzer.h"

/* abstraction for the send_over_network function */
enum sock_type {INTERNET_SOCKET = 0, UNIX_DOMAIN_SOCKET};

#define LOCAL_PATHNAME "/var/tmp/stadsocket"

static int vfs_smb_traffic_analyzer_debug_level = DBGC_VFS;

static enum sock_type smb_traffic_analyzer_connMode(vfs_handle_struct *handle)
{
	connection_struct *conn = handle->conn;
        const char *Mode;
        Mode=lp_parm_const_string(SNUM(conn), "smb_traffic_analyzer","mode", \
			"internet_socket");
	if (strstr(Mode,"unix_domain_socket")) {
		return UNIX_DOMAIN_SOCKET;
	} else {
		return INTERNET_SOCKET;
	}
}


/* Connect to an internet socket */
static int smb_traffic_analyzer_connect_inet_socket(vfs_handle_struct *handle,
					const char *name, uint16_t port)
{
	/* Create a streaming Socket */
	int sockfd = -1;
	struct addrinfo hints;
	struct addrinfo *ailist = NULL;
	struct addrinfo *res = NULL;
	int ret;

	ZERO_STRUCT(hints);
	/* By default make sure it supports TCP. */
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_ADDRCONFIG;

	ret = getaddrinfo(name,
			NULL,
			&hints,
			&ailist);

        if (ret) {
		DEBUG(3,("smb_traffic_analyzer_connect_inet_socket: "
			"getaddrinfo failed for name %s [%s]\n",
                        name,
                        gai_strerror(ret) ));
		return -1;
        }

	DEBUG(3,("smb_traffic_analyzer: Internet socket mode. Hostname: %s,"
		"Port: %i\n", name, port));

	for (res = ailist; res; res = res->ai_next) {
		struct sockaddr_storage ss;
		NTSTATUS status;

		if (!res->ai_addr || res->ai_addrlen == 0) {
			continue;
		}

		ZERO_STRUCT(ss);
		memcpy(&ss, res->ai_addr, res->ai_addrlen);

		status = open_socket_out(&ss, port, 10000, &sockfd);
		if (NT_STATUS_IS_OK(status)) {
			break;
		}
	}

	if (ailist) {
		freeaddrinfo(ailist);
	}

        if (sockfd == -1) {
		DEBUG(1, ("smb_traffic_analyzer: unable to create "
			"socket, error is %s",
			strerror(errno)));
		return -1;
	}

	return sockfd;
}

/* Connect to a unix domain socket */
static int smb_traffic_analyzer_connect_unix_socket(vfs_handle_struct *handle,
						const char *name)
{
	/* Create the socket to stad */
	int len, sock;
	struct sockaddr_un remote;

	DEBUG(7, ("smb_traffic_analyzer_connect_unix_socket: "
			"Unix domain socket mode. Using %s\n",
			name ));

	if ((sock = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
		DEBUG(1, ("smb_traffic_analyzer_connect_unix_socket: "
			"Couldn't create socket, "
			"make sure stad is running!\n"));
		return -1;
	}
	remote.sun_family = AF_UNIX;
	strlcpy(remote.sun_path, name,
		    sizeof(remote.sun_path));
	len=strlen(remote.sun_path) + sizeof(remote.sun_family);
	if (connect(sock, (struct sockaddr *)&remote, len) == -1 ) {
		DEBUG(1, ("smb_traffic_analyzer_connect_unix_socket: "
			"Could not connect to "
			"socket, make sure\nstad is running!\n"));
		close(sock);
		return -1;
	}
	return sock;
}

/* Private data allowing shared connection sockets. */
struct refcounted_sock {
	struct refcounted_sock *next, *prev;
	char *name;
	uint16_t port;
	int sock;
	unsigned int ref_count;
};


/* The marshaller for the protocol version 2. */
static char *smb_traffic_analyzer_create_string( struct tm *tm, \
	int seconds, vfs_handle_struct *handle, \
	char *username, int vfs_operation, int count, ... )
{
	
	va_list ap;
	char *arg = NULL;
	int len;
	char *header = NULL;
	char *buf = NULL;
	char *timestr = NULL;
	char *opstr = NULL;
	char *sidstr = NULL;
	char *userstr = NULL;
	char *usersid = NULL;
	const char *total_anonymization = NULL;
	const char *anon_prefix = NULL;
	/*
	 * first create the data that is transfered with any VFS op
	 * These are, in the following order:
	 * number of data to come [6 in v2.0]
	 * 1.vfs_operation identifier
	 * 2.username
	 * 3.user-SID
	 * 4.affected file + full path
	 * 5.domain
	 * 6.timestamp
	 */

	opstr = talloc_asprintf(talloc_tos(), "%i", vfs_operation);
	len = strlen(opstr);
	buf = talloc_asprintf(talloc_tos(), "%04u%s", len, opstr);

	/*
	 * Handle anonymization. In protocol v2, we have to anonymize
	 * both the SID and the username.
	 */
	total_anonymization=lp_parm_const_string(SNUM(handle->conn),
					"smb_traffic_analyzer",
					"total_anonymization", NULL);

	anon_prefix=lp_parm_const_string(SNUM(handle->conn),
					"smb_traffic_analyzer",
					"anonymize_prefix", NULL );
	usersid = dom_sid_string(talloc_tos(),
		&handle->conn->server_info->ptok->user_sids[0]);
	if (anon_prefix != NULL) {
		if (total_anonymization != NULL) {
			userstr = talloc_asprintf(talloc_tos(), "%s",
							anon_prefix);			
			sidstr = talloc_asprintf(talloc_tos(), "%s",
							anon_prefix);
		} else {
			userstr = talloc_asprintf(talloc_tos(), "%s%i",
				anon_prefix,
				str_checksum(username));
			sidstr = talloc_asprintf(talloc_tos(), "%s%i",
				anon_prefix,
				str_checksum(usersid));
		}
	} else {
		userstr = username;
		sidstr = usersid;
	}

	len = strlen( userstr );
	buf = talloc_asprintf_append(buf, "%04u%s", len, userstr);
	len = strlen( sidstr );
	buf = talloc_asprintf_append(buf, "%04u%s", len, sidstr);
	len = strlen( handle->conn->connectpath );
	buf = talloc_asprintf_append( buf, "%04u%s", len, \
		handle->conn->connectpath );
	len = strlen( pdb_get_domain(handle->conn->server_info->sam_account) );
	buf = talloc_asprintf_append( buf, "%04u%s", len, \
		pdb_get_domain(handle->conn->server_info->sam_account) );
	timestr = talloc_asprintf(talloc_tos(), \
		"%04d-%02d-%02d %02d:%02d:%02d.%03d", \
		tm->tm_year+1900, \
		tm->tm_mon+1, \
		tm->tm_mday, \
		tm->tm_hour, \
		tm->tm_min, \
		tm->tm_sec, \
		(int)seconds);
	len = strlen( timestr );
	buf = talloc_asprintf_append( buf, "%04u%s", len, timestr);
	
	va_start( ap, count );
	while ( count-- ) {
		arg = va_arg( ap, char * );
		/*
		 *  protocol v2 sends a four byte string
		 * as a header to each block, including
		 * the numbers of bytes to come in the
		 * next string.
		 */
		len = strlen( arg );
		buf = talloc_asprintf_append( buf, "%04u%s", len, arg);
	}
	va_end( ap );
	return buf;
}

static void smb_traffic_analyzer_send_data(vfs_handle_struct *handle,
					void *data,
					enum vfs_id vfs_operation )
{
	struct refcounted_sock *rf_sock = NULL;
	struct timeval tv;
	time_t tv_sec;
	struct tm *tm = NULL;
	int seconds;
	char *str = NULL;
	char *username = NULL;
	char *header = NULL;
	const char *anon_prefix = NULL;
	const char *total_anonymization = NULL;
	const char *protocol_version = NULL;
	bool Write = false;
	size_t len;
	char state_flags[9] = "000000\0";

	SMB_VFS_HANDLE_GET_DATA(handle, rf_sock, struct refcounted_sock, return);

	if (rf_sock == NULL || rf_sock->sock == -1) {
		DEBUG(1, ("smb_traffic_analyzer_send_data: socket is "
			"closed\n"));
		return;
	}

	GetTimeOfDay(&tv);
	tv_sec = convert_timespec_to_time_t(convert_timeval_to_timespec(tv));
	tm = localtime(&tv_sec);
	if (!tm) {
		return;
	}
	seconds=(float) (tv.tv_usec / 1000);

	/*
	 * Check if anonymization is required, and if yes do this only if
	 * we run on protocol version 1. Anonynization for protocol v2 is
	 * handled in it's marshaller function.
	 */
	total_anonymization=lp_parm_const_string(SNUM(handle->conn),"smb_traffic_analyzer",
					"total_anonymization", NULL);

	anon_prefix=lp_parm_const_string(SNUM(handle->conn),"smb_traffic_analyzer",\
					"anonymize_prefix", NULL );

	protocol_version = lp_parm_const_string(SNUM(handle->conn),
					"smb_traffic_analyzer",
					"protocol_version", NULL );

	if (anon_prefix!=NULL && strcmp(protocol_version,"V2") != 0) {
		if (total_anonymization!=NULL) {
			username = talloc_asprintf(talloc_tos(),
				"%s",
				anon_prefix);
		} else {
			username = talloc_asprintf(talloc_tos(),
				"%s%i",
				anon_prefix,
				str_checksum(
					handle->conn->server_info->sanitized_username )	); 
		}

	} else {
		username = handle->conn->server_info->sanitized_username;
	}

	if (!username) {
		return;
	}

	if ( protocol_version == NULL || strcmp( protocol_version,"V1") == 0) {

		struct rw_data *s_data = (struct rw_data *) data;

		/*
		 * in case of protocol v1, ignore any vfs operations
		 * except read,pread,write,pwrite, and set the "Write"
		 * bool accordingly, send data and return.
		 */
		if ( vfs_operation > vfs_id_pwrite ) return;

		if ( vfs_operation <= vfs_id_pread ) Write=false;
			else Write=true;

		str = talloc_asprintf(talloc_tos(),
			"V1,%u,\"%s\",\"%s\",\"%c\",\"%s\",\"%s\","
			"\"%04d-%02d-%02d %02d:%02d:%02d.%03d\"\n",
			(unsigned int) s_data->len,
			username,
			pdb_get_domain(handle->conn->server_info->sam_account),
			Write ? 'W' : 'R',
			handle->conn->connectpath,
			s_data->filename,
			tm->tm_year+1900,
			tm->tm_mon+1,
			tm->tm_mday,
			tm->tm_hour,
			tm->tm_min,
			tm->tm_sec,
			(int)seconds);
		if (write_data(rf_sock->sock, str, len) != len) {
                	DEBUG(1, ("smb_traffic_analyzer_send_data_socket: "
			"error sending V1 protocol data to socket!\n"));
		return;
		}

	} else if ( strcmp( protocol_version, "V2") == 0) {

		switch( vfs_operation ) {
		case vfs_id_mkdir: ;
			str = smb_traffic_analyzer_create_string( tm, \
				seconds, handle, username, vfs_id_mkdir, 3,\
				((struct mkdir_data *) data)->path, \
				talloc_asprintf( talloc_tos(), "%u", \
				((struct mkdir_data *) data)->mode), \
				talloc_asprintf( talloc_tos(), "%u", \
				((struct mkdir_data *) data)->result ));
			break;
		case vfs_id_rmdir: ;
			str = smb_traffic_analyzer_create_string( tm, \
				seconds, handle, username, vfs_id_rmdir, 2,\
				((struct rmdir_data *) data)->path, \
				talloc_asprintf( talloc_tos(), "%u", \
				((struct rmdir_data *) data)->result ));
			break;
		case vfs_id_rename: ;
			str = smb_traffic_analyzer_create_string( tm, \
				seconds, handle, username, vfs_id_rename, 3,\
				((struct rename_data *) data)->src, \
				((struct rename_data *) data)->dst,
				talloc_asprintf(talloc_tos(), "%u", \
				((struct rename_data *) data)->result));
			break;
		case vfs_id_chdir: ;
			str = smb_traffic_analyzer_create_string( tm, \
				seconds, handle, username, vfs_id_chdir, 2,\
				((struct chdir_data *) data)->path, \
				talloc_asprintf(talloc_tos(), "%u", \
				((struct chdir_data *) data)->result));
			break;

		case vfs_id_write:
		case vfs_id_pwrite:
		case vfs_id_read:
		case vfs_id_pread: ;
			str = smb_traffic_analyzer_create_string( tm, \
				seconds, handle, username, vfs_operation, 2,\
				((struct rw_data *) data)->filename, \
				talloc_asprintf(talloc_tos(), "%u", \
				((struct rw_data *) data)->len));
			break;
		default:
			DEBUG(1, ("smb_traffic_analyzer: error! "
				"wrong VFS operation id detected!\n"));
			return;
		}

	} else {
		DEBUG(1, ("smb_traffic_analyzer_send_data_socket: "
			"error, unkown protocol given!\n"));
		return;
	}

	if (!str) {
		DEBUG(1, ("smb_traffic_analyzer_send_data: "
			"unable to create string to send!\n"));
		return;
	}


	/*
	 * If configured, optain the key and run AES encryption
	 * over the data.
	 */
	size_t size;
	become_root();
	char *akey = (char *) secrets_fetch("smb_traffic_analyzer_key", &size);
	unbecome_root();
	if ( akey != NULL ) {
		char crypted[18], *filler, *output;
		int h,d,s1,s2;
		state_flags[2] = 'E';
		DEBUG(10, ("smb_traffic_analyzer_send_data_socket: a key was"
			" found, encrypting data!\n"));
		AES_KEY key;
		samba_AES_set_encrypt_key(akey, 128, &key);
		free(akey);
		s1 = strlen(str) / 16;
		s2 = strlen(str) % 16;
		DEBUG(10, ("smb_traffic_analyzer_send_data_socket: found %i"
			" blocks, %i missing bytes.\n",
			s1,s2));
		filler = talloc_asprintf( talloc_tos(), "................" );
		for (h = 0; h < s2; h++) {
			*(filler+h)=*(str+(s1*16)+h);
		}
		DEBUG(10, ("smb_traffic_analyzer_send_data_socket: created %s"
			" as filling block.\n", filler));
		output = talloc_array(talloc_tos(), char, (s1*16)+17 );
		d=0;
		for (h = 0; h < s1; h++) {
			samba_AES_encrypt(str+(16*h), crypted, &key);
			for (d = 0; d<16; d++) output[d+(16*h)]=crypted[d];
		}
		samba_AES_encrypt( str+(16*h), filler, &key );
		for (d = 0;d < 16; d++) output[d+(16*h)]=*(filler+d);
		len = (s1*16)+16;
		header = talloc_asprintf( talloc_tos(), "V2.%s%017u",
						state_flags, len);

		DEBUG(10, ("smb_traffic_analyzer_send_data_socket:"
			" header created for crypted data: %s\n", header));
		len = strlen(header);
		if (write_data(rf_sock->sock, header, len) != len) {
			DEBUG(1, ("smb_traffic_analyzer_send_data_socket: "
						"error sending the header"
						 " over the socket!\n"));
		}
		len = (s1*16)+16;
		if (write_data(rf_sock->sock, output, len) != len) {
			DEBUG(1, ("smb_traffic_analyzer_send_data_socket: "
				"error sending crypted data to socket!\n"));
		}
	return;
	}

        len = strlen(str);
        header = talloc_asprintf(talloc_tos(), "V2.%s%017u", state_flags, len);
        DEBUG(10, ("smb_traffic_analyzer_send_data_socket: header created:"
                                                        "%s\n", header));
        len = strlen(header);
        if (write_data(rf_sock->sock, header, len) != len) {
                DEBUG(1, ("smb_traffic_analyzer_send_data_socket: error "
                        "sending the header over the socket!\n"));
        }
        len = strlen(str);
	DEBUG(10, ("smb_traffic_analyzer_send_data_socket: going to send "
			"data block: %s\n",str));
	if (write_data(rf_sock->sock, str, len) != len) {
		DEBUG(1, ("smb_traffic_analyzer_send_data_socket: "
			"error sending data to socket!\n"));
		return ;
	}
}

static struct refcounted_sock *sock_list;

static void smb_traffic_analyzer_free_data(void **pptr)
{
	struct refcounted_sock *rf_sock = *(struct refcounted_sock **)pptr;
	if (rf_sock == NULL) {
		return;
	}
	rf_sock->ref_count--;
	if (rf_sock->ref_count != 0) {
		return;
	}
	if (rf_sock->sock != -1) {
		close(rf_sock->sock);
	}
	DLIST_REMOVE(sock_list, rf_sock);
	TALLOC_FREE(rf_sock);
}

static int smb_traffic_analyzer_connect(struct vfs_handle_struct *handle,
                         const char *service,
                         const char *user)
{
	connection_struct *conn = handle->conn;
	enum sock_type st = smb_traffic_analyzer_connMode(handle);
	struct refcounted_sock *rf_sock = NULL;
	const char *name = (st == UNIX_DOMAIN_SOCKET) ? LOCAL_PATHNAME :
				lp_parm_const_string(SNUM(conn),
					"smb_traffic_analyzer",
				"host", "localhost");
	uint16_t port = (st == UNIX_DOMAIN_SOCKET) ? 0 :
				atoi( lp_parm_const_string(SNUM(conn),
				"smb_traffic_analyzer", "port", "9430"));
	int ret = SMB_VFS_NEXT_CONNECT(handle, service, user);

	if (ret < 0) {
		return ret;
	}

	/* Are we already connected ? */
	for (rf_sock = sock_list; rf_sock; rf_sock = rf_sock->next) {
		if (port == rf_sock->port &&
				(strcmp(name, rf_sock->name) == 0)) {
			break;
		}
	}

	/* If we're connected already, just increase the
 	 * reference count. */
	if (rf_sock) {
		rf_sock->ref_count++;
	} else {
		/* New connection. */
		rf_sock = TALLOC_ZERO_P(NULL, struct refcounted_sock);
		if (rf_sock == NULL) {
			SMB_VFS_NEXT_DISCONNECT(handle);
			errno = ENOMEM;
			return -1;
		}
		rf_sock->name = talloc_strdup(rf_sock, name);
		if (rf_sock->name == NULL) {
			SMB_VFS_NEXT_DISCONNECT(handle);
			TALLOC_FREE(rf_sock);
			errno = ENOMEM;
			return -1;
		}
		rf_sock->port = port;
		rf_sock->ref_count = 1;

		if (st == UNIX_DOMAIN_SOCKET) {
			rf_sock->sock = smb_traffic_analyzer_connect_unix_socket(handle,
							name);
		} else {

			rf_sock->sock = smb_traffic_analyzer_connect_inet_socket(handle,
							name,
							port);
		}
		if (rf_sock->sock == -1) {
			SMB_VFS_NEXT_DISCONNECT(handle);
			TALLOC_FREE(rf_sock);
			return -1;
		}
		DLIST_ADD(sock_list, rf_sock);
	}

	/* Store the private data. */
	SMB_VFS_HANDLE_SET_DATA(handle, rf_sock, smb_traffic_analyzer_free_data,
				struct refcounted_sock, return -1);
	return 0;
}

/* VFS Functions */
static int smb_traffic_analyzer_chdir(vfs_handle_struct *handle, \
			const char *path)
{
	struct chdir_data s_data;
	s_data.result = SMB_VFS_NEXT_CHDIR(handle, path);
	s_data.path = path;
	DEBUG(10, ("smb_traffic_analyzer_chdir: CHDIR: %s\n", path));
	smb_traffic_analyzer_send_data(handle, &s_data, vfs_id_chdir);
	return s_data.result;
}

static int smb_traffic_analyzer_rename(vfs_handle_struct *handle, \
		const struct smb_filename *smb_fname_src,
		const struct smb_filename *smb_fname_dst)
{
	struct rename_data s_data;
	s_data.result = SMB_VFS_NEXT_RENAME(handle, smb_fname_src, \
		smb_fname_dst);
	s_data.src = smb_fname_src->base_name;
	s_data.dst = smb_fname_dst->base_name;
	DEBUG(10, ("smb_traffic_analyzer_rename: RENAME: %s / %s\n",
		smb_fname_src->base_name,
		smb_fname_dst->base_name));
	smb_traffic_analyzer_send_data(handle, &s_data, vfs_id_rename);
	return s_data.result;
}

static int smb_traffic_analyzer_rmdir(vfs_handle_struct *handle, \
			const char *path)
{
	struct rmdir_data s_data;
	s_data.result = SMB_VFS_NEXT_RMDIR(handle, path);
	s_data.path = path;
	DEBUG(10, ("smb_traffic_analyzer_rmdir: RMDIR: %s\n", path));
	smb_traffic_analyzer_send_data(handle, &s_data, vfs_id_rmdir);
	return s_data.result;
}

static int smb_traffic_analyzer_mkdir(vfs_handle_struct *handle, \
			const char *path, mode_t mode)
{
	struct mkdir_data s_data;
	s_data.result = SMB_VFS_NEXT_MKDIR(handle, path, mode);
	s_data.path = path;
	s_data.mode = mode;
	DEBUG(10, ("smb_traffic_analyzer_mkdir: MKDIR: %s\n", path));
	smb_traffic_analyzer_send_data(handle,
			&s_data,
			vfs_id_mkdir);
	return s_data.result;
}

static ssize_t smb_traffic_analyzer_read(vfs_handle_struct *handle, \
				files_struct *fsp, void *data, size_t n)
{
	struct rw_data s_data;

	s_data.len = SMB_VFS_NEXT_READ(handle, fsp, data, n);
	s_data.filename = fsp->fsp_name->base_name;
	DEBUG(10, ("smb_traffic_analyzer_read: READ: %s\n", fsp_str_dbg(fsp)));

	smb_traffic_analyzer_send_data(handle,
			&s_data,
			vfs_id_read);
	return s_data.len;
}


static ssize_t smb_traffic_analyzer_pread(vfs_handle_struct *handle, \
		files_struct *fsp, void *data, size_t n, SMB_OFF_T offset)
{
	struct rw_data s_data;

	s_data.len = SMB_VFS_NEXT_PREAD(handle, fsp, data, n, offset);
	s_data.filename = fsp->fsp_name->base_name;
	DEBUG(10, ("smb_traffic_analyzer_pread: PREAD: %s\n",
		   fsp_str_dbg(fsp)));

	smb_traffic_analyzer_send_data(handle,
			&s_data,
			vfs_id_pread);

	return s_data.len;
}

static ssize_t smb_traffic_analyzer_write(vfs_handle_struct *handle, \
			files_struct *fsp, const void *data, size_t n)
{
	struct rw_data s_data;

	s_data.len = SMB_VFS_NEXT_WRITE(handle, fsp, data, n);
	s_data.filename = fsp->fsp_name->base_name;
	DEBUG(10, ("smb_traffic_analyzer_write: WRITE: %s\n",
		   fsp_str_dbg(fsp)));

	smb_traffic_analyzer_send_data(handle,
			&s_data,
			vfs_id_write);
	return s_data.len;
}

static ssize_t smb_traffic_analyzer_pwrite(vfs_handle_struct *handle, \
	     files_struct *fsp, const void *data, size_t n, SMB_OFF_T offset)
{
	struct rw_data s_data;

	s_data.len = SMB_VFS_NEXT_PWRITE(handle, fsp, data, n, offset);
	s_data.filename = fsp->fsp_name->base_name;
	DEBUG(10, ("smb_traffic_analyzer_pwrite: PWRITE: %s\n", \
		fsp_str_dbg(fsp)));

	smb_traffic_analyzer_send_data(handle,
			&s_data,
			vfs_id_pwrite);
	return s_data.len;
}

static struct vfs_fn_pointers vfs_smb_traffic_analyzer_fns = {
        .connect_fn = smb_traffic_analyzer_connect,
	.vfs_read = smb_traffic_analyzer_read,
	.pread = smb_traffic_analyzer_pread,
	.write = smb_traffic_analyzer_write,
	.pwrite = smb_traffic_analyzer_pwrite,
	.mkdir = smb_traffic_analyzer_mkdir,
	.rename = smb_traffic_analyzer_rename,
	.chdir = smb_traffic_analyzer_chdir
};

/* Module initialization */
NTSTATUS vfs_smb_traffic_analyzer_init(void)
{
	NTSTATUS ret = smb_register_vfs(SMB_VFS_INTERFACE_VERSION,
					"smb_traffic_analyzer",
					&vfs_smb_traffic_analyzer_fns);

	if (!NT_STATUS_IS_OK(ret)) {
		return ret;
	}

	vfs_smb_traffic_analyzer_debug_level =
		debug_add_class("smb_traffic_analyzer");

	if (vfs_smb_traffic_analyzer_debug_level == -1) {
		vfs_smb_traffic_analyzer_debug_level = DBGC_VFS;
		DEBUG(1, ("smb_traffic_analyzer_init: Couldn't register custom"
			 "debugging class!\n"));
	} else {
		DEBUG(3, ("smb_traffic_analyzer_init: Debug class number of"
			"'smb_traffic_analyzer': %d\n", \
			vfs_smb_traffic_analyzer_debug_level));
	}

	return ret;
}
