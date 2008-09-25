/*
 * traffic-analyzer VFS module. Measure the smb traffic users create
 * on the net.
 *
 * Copyright (C) Holger Hetterich, 2008
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

/* abstraction for the send_over_network function */
#define UNIX_DOMAIN_SOCKET 1
#define INTERNET_SOCKET 0


/* Prototypes */

extern userdom_struct current_user_info;

static int vfs_smb_traffic_analyzer_debug_level = DBGC_VFS;

NTSTATUS vfs_smb_traffic_analyzer_init(void);

static ssize_t smb_traffic_analyzer_write(vfs_handle_struct *handle,
		files_struct *fsp, const void *data, size_t n);

static ssize_t smb_traffic_analyzer_read(vfs_handle_struct *handle,
		files_struct *fsp, void *data, size_t n);

static ssize_t smb_traffic_analyzer_pwrite(vfs_handle_struct *handle,
		files_struct *fsp, const void *data, size_t n,
		SMB_OFF_T offset);

static ssize_t smb_traffic_analyzer_pread(vfs_handle_struct *handle,
		files_struct *fsp, void *data, size_t n, SMB_OFF_T offset);


/* VFS operations we use */

static vfs_op_tuple smb_traffic_analyzer_tuples[] = {

	{SMB_VFS_OP(smb_traffic_analyzer_read),	SMB_VFS_OP_READ,
	 SMB_VFS_LAYER_LOGGER},
	{SMB_VFS_OP(smb_traffic_analyzer_pread), SMB_VFS_OP_PREAD,
	 SMB_VFS_LAYER_LOGGER},
	{SMB_VFS_OP(smb_traffic_analyzer_write), SMB_VFS_OP_WRITE,
	 SMB_VFS_LAYER_LOGGER},
	{SMB_VFS_OP(smb_traffic_analyzer_pwrite), SMB_VFS_OP_PWRITE,
	 SMB_VFS_LAYER_LOGGER},
       	{SMB_VFS_OP(NULL),SMB_VFS_OP_NOOP,SMB_VFS_LAYER_NOOP}

	};


/* Module initialization */

NTSTATUS vfs_smb_traffic_analyzer_init(void)
{
	NTSTATUS ret = smb_register_vfs(SMB_VFS_INTERFACE_VERSION, \
		"smb_traffic_analyzer",	smb_traffic_analyzer_tuples);

	if (!NT_STATUS_IS_OK(ret))
		return ret;

	vfs_smb_traffic_analyzer_debug_level =
		debug_add_class("smb_traffic_analyzer");

	if (vfs_smb_traffic_analyzer_debug_level == -1) {
		vfs_smb_traffic_analyzer_debug_level = DBGC_VFS;
		DEBUG(1, ("smb_traffic_analyzer: Couldn't register custom"
			 "debugging class!\n"));
	} else {
		DEBUG(3, ("smb_traffic_analyzer: Debug class number of"
			"'smb_traffic_analyzer': %d\n", \
			vfs_smb_traffic_analyzer_debug_level));
	}

	return ret;
}

/* create the timestamp in sqlite compatible format */
static void get_timestamp( char *String )
{
	struct timeval tv;
	struct timezone tz;
	struct tm *tm;
	int seconds;

	gettimeofday(&tv, &tz);
 	tm=localtime(&tv.tv_sec);
	seconds=(float) (tv.tv_usec / 1000);

	fstr_sprintf(String,"%04d-%02d-%02d %02d:%02d:%02d.%03d", \
			tm->tm_year+1900, tm->tm_mon+1, tm->tm_mday, \
			tm->tm_hour, tm->tm_min, tm->tm_sec, (int)seconds);

}

static int smb_traffic_analyzer_connMode( vfs_handle_struct *handle)
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

/* Send data over a internet socket */
static void smb_traffic_analyzer_send_data_inet_socket( char *String,
			vfs_handle_struct *handle, const char *file_name,
			bool Write)
{
	/* Create a streaming Socket */
	const char *Hostname;
	int sockfd = -1;
        uint16_t port;
	struct addrinfo hints;
	struct addrinfo *ailist = NULL;
	struct addrinfo *res = NULL;
	char Sender[200];
	char TimeStamp[200];
	connection_struct *conn = handle->conn;
	int ret;

	/* get port number, target system from the config parameters */
	Hostname=lp_parm_const_string(SNUM(conn), "smb_traffic_analyzer", 
				"host", "localhost");

	ZERO_STRUCT(hints);
	/* By default make sure it supports TCP. */
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_ADDRCONFIG;

	ret = getaddrinfo(Hostname,
			NULL,
			&hints,
			&ailist);

        if (ret) {
		DEBUG(3,("smb_traffic_analyzer_send_data_inet_socket: "
			"getaddrinfo failed for name %s [%s]\n",
                        Hostname,
                        gai_strerror(ret) ));
		return;
        }

	port = atoi( lp_parm_const_string(SNUM(conn), 
				"smb_traffic_analyzer", "port", "9430"));

	DEBUG(3,("smb_traffic_analyzer: Internet socket mode. Hostname: %s,"
		"Port: %i\n", Hostname, port));

	for (res = ailist; res; res = res->ai_next) {
		struct sockaddr_storage ss;

		if (!res->ai_addr || res->ai_addrlen == 0) {
			continue;
		}

		ZERO_STRUCT(ss);
		memcpy(&ss, res->ai_addr, res->ai_addrlen);

		sockfd = open_socket_out(SOCK_STREAM, &ss, port, 10000);
		if (sockfd != -1) {
			break;
		}
	}

	if (ailist) {
		freeaddrinfo(ailist);
	}

        if (sockfd == -1) {
		DEBUG(1, ("smb_traffic_analyzer: unable to create socket, error is %s", 
			strerror(errno)));
		return;
	}

	strlcpy(Sender, String, sizeof(Sender));
	strlcat(Sender, ",\"", sizeof(Sender));
	strlcat(Sender, get_current_username(), sizeof(Sender));
	strlcat(Sender, "\",\"", sizeof(Sender));
	strlcat(Sender, current_user_info.domain, sizeof(Sender));
	strlcat(Sender, "\",\"", sizeof(Sender));
        if (Write)
		strlcat(Sender, "W", sizeof(Sender));
	else
		strlcat(Sender, "R", sizeof(Sender));
	strlcat(Sender, "\",\"", sizeof(Sender));
	strlcat(Sender, handle->conn->connectpath, sizeof(Sender));
	strlcat(Sender, "\",\"", sizeof(Sender) - 1);
	strlcat(Sender, file_name, sizeof(Sender) - 1);
	strlcat(Sender, "\",\"", sizeof(Sender) - 1);
        get_timestamp(TimeStamp);
	strlcat(Sender, TimeStamp, sizeof(Sender) - 1);
	strlcat(Sender, "\");", sizeof(Sender) - 1);
        DEBUG(10, ("smb_traffic_analyzer: sending %s\n", Sender));
        if ( send(sockfd, Sender, strlen(Sender), 0) == -1 ) {
                DEBUG(1, ("smb_traffic_analyzer: error sending data to socket!\n"));
        	close(sockfd);
                return ;
        }

        /* one operation, close the socket */
        close(sockfd);
}



/* Send data over a unix domain socket */
static void smb_traffic_analyzer_send_data_unix_socket( char *String ,
			vfs_handle_struct *handle, const char *file_name, 
			bool Write)
{
	/* Create the socket to stad */
	int len, sock;
	struct sockaddr_un remote;
        char Sender[200];
        char TimeStamp[200];

	DEBUG(7, ("smb_traffic_analyzer: Unix domain socket mode. Using "
			"/var/tmp/stadsocket\n"));

	if ((sock = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
		DEBUG(1, ("smb_traffic_analyzer: Couldn create socket,"
			"make sure stad is running!\n"));
	}
	remote.sun_family = AF_UNIX;
	strlcpy(remote.sun_path, "/var/tmp/stadsocket", 
		    sizeof(remote.sun_path));
	len=strlen(remote.sun_path) + sizeof(remote.sun_family);
	if (connect(sock, (struct sockaddr *)&remote, len) == -1 ) {
		DEBUG(1, ("smb_traffic_analyzer: Could not connect to"
			"socket, make sure\nstad is running!\n"));
		close(sock);
		return;
	}
	strlcpy(Sender, String, sizeof(Sender));
	strlcat(Sender, ",\"", sizeof(Sender));
	strlcat(Sender, get_current_username(), sizeof(Sender));
	strlcat(Sender,"\",\"",sizeof(Sender));
	strlcat(Sender, current_user_info.domain, sizeof(Sender));
	strlcat(Sender, "\",\"", sizeof(Sender));
	if (Write)
		strlcat(Sender, "W", sizeof(Sender));
	else
		strlcat(Sender, "R", sizeof(Sender));
	strlcat(Sender, "\",\"", sizeof(Sender));
	strlcat(Sender, handle->conn->connectpath, sizeof(Sender));
	strlcat(Sender, "\",\"", sizeof(Sender));
	strlcat(Sender, file_name, sizeof(Sender));
	strlcat(Sender, "\",\"", sizeof(Sender));
	get_timestamp(TimeStamp);
	strlcat(Sender, TimeStamp, sizeof(Sender));
	strlcat(Sender, "\");", sizeof(Sender));

	DEBUG(10, ("smb_traffic_analyzer: sending %s\n", Sender));
	if ( send(sock, Sender, strlen(Sender), 0) == -1 ) {
		DEBUG(1, ("smb_traffic_analyzer: error sending data to"
			"socket!\n"));
		close(sock);
		return;
	}

	/* one operation, close the socket */
	close(sock);
	return;
}

static void smb_traffic_analyzer_send_data( char *Buffer , vfs_handle_struct \
			*handle, char *file_name, bool Write, files_struct *fsp)
{

        if (smb_traffic_analyzer_connMode(handle) == UNIX_DOMAIN_SOCKET) {
                smb_traffic_analyzer_send_data_unix_socket(Buffer, handle, \
							fsp->fsp_name, Write);
        } else {
                smb_traffic_analyzer_send_data_inet_socket(Buffer, handle, \
							fsp->fsp_name, Write);
        }
}



/* VFS Functions: write, read, pread, pwrite for now */

static ssize_t smb_traffic_analyzer_read(vfs_handle_struct *handle, \
				files_struct *fsp, void *data, size_t n)
{
	ssize_t result;
        fstring Buffer;

	result = SMB_VFS_NEXT_READ(handle, fsp, data, n);
	DEBUG(10, ("smb_traffic_analyzer: READ: %s\n", fsp->fsp_name ));

	fstr_sprintf(Buffer, "%u", (uint) result);

	smb_traffic_analyzer_send_data(Buffer, handle, fsp->fsp_name, false, fsp);
	return result;
}


static ssize_t smb_traffic_analyzer_pread(vfs_handle_struct *handle, \
		files_struct *fsp, void *data, size_t n, SMB_OFF_T offset)
{
	ssize_t result;
        fstring Buffer;

	result = SMB_VFS_NEXT_PREAD(handle, fsp, data, n, offset);

	DEBUG(10, ("smb_traffic_analyzer: READ: %s\n", fsp->fsp_name ));

	fstr_sprintf(Buffer,"%u", (uint) result);
	smb_traffic_analyzer_send_data(Buffer, handle, fsp->fsp_name, false, fsp);

	return result;
}

static ssize_t smb_traffic_analyzer_write(vfs_handle_struct *handle, \
			files_struct *fsp, const void *data, size_t n)
{
	ssize_t result;
        fstring Buffer;

	result = SMB_VFS_NEXT_WRITE(handle, fsp, data, n);

	DEBUG(10, ("smb_traffic_analyzer: WRITE: %s\n", fsp->fsp_name ));

	fstr_sprintf(Buffer, "%u", (uint) result);
	smb_traffic_analyzer_send_data(Buffer, handle, fsp->fsp_name, \
								true, fsp );
	return result;
}

static ssize_t smb_traffic_analyzer_pwrite(vfs_handle_struct *handle, \
	     files_struct *fsp, const void *data, size_t n, SMB_OFF_T offset)
{
	ssize_t result;
        fstring Buffer;

	result = SMB_VFS_NEXT_PWRITE(handle, fsp, data, n, offset);

	DEBUG(10, ("smb_traffic_analyzer: PWRITE: %s\n", fsp->fsp_name ));

	fstr_sprintf(Buffer, "%u", (uint) result);
	smb_traffic_analyzer_send_data(Buffer, handle, fsp->fsp_name, true, fsp);
	return result;
}
