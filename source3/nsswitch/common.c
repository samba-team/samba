/* 
   Unix SMB/Netbios implementation.
   Version 2.0

   winbind client common code

   Copyright (C) Tim Potter 2000
   Copyright (C) Andrew Tridgell 2000
   
   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public
   License as published by the Free Software Foundation; either
   version 2 of the License, or (at your option) any later version.
   
   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.
   
   You should have received a copy of the GNU Library General Public
   License along with this library; if not, write to the
   Free Software Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA  02111-1307, USA.   
*/

#include "ntdom_config.h"
#include "winbindd_ntdom.h"

/* Global variables.  These are effectively the client state information */

static int established_socket = -1;           /* fd for winbindd socket */

/*
 * Utility and helper functions
 */

void init_request(struct winbindd_request *req,int rq_type)
{
        static char *domain_env;
        static BOOL initialised;

	req->cmd = rq_type;
	req->pid = getpid();
	req->domain[0] = '\0';

	if (!initialised) {
		initialised = True;
		domain_env = getenv(WINBINDD_DOMAIN_ENV);
	}

	if (domain_env) {
		strncpy(req->domain, domain_env,
			sizeof(req->domain) - 1);
		req->domain[sizeof(req->domain) - 1] = '\0';
	}
}

/* Close established socket */

void close_sock(void)
{
    if (established_socket != -1) {
	    close(established_socket);
	    established_socket = -1;
    }
}

/* Connect to winbindd socket */

static int open_pipe_sock(void)
{
    struct sockaddr_un sunaddr;
    static pid_t our_pid;
    struct stat st;
    pstring path;

    if (our_pid != getpid()) {
        if (established_socket != -1) {
            close(established_socket);
        }
        established_socket = -1;
        our_pid = getpid();
    }

    if (established_socket != -1) {
        return established_socket;
    }

    /* Check permissions on unix socket directory */

    if (lstat(WINBINDD_SOCKET_DIR, &st) == -1) {
        return -1;
    }

    if (!S_ISDIR(st.st_mode) || (st.st_uid != 0)) {
        return -1;
    }

    /* Connect to socket */

    strncpy(path, WINBINDD_SOCKET_DIR, sizeof(path) - 1);
    path[sizeof(path) - 1] = '\0';

    strncat(path, "/", sizeof(path) - 1);
    path[sizeof(path) - 1] = '\0';

    strncat(path, WINBINDD_SOCKET_NAME, sizeof(path) - 1);
    path[sizeof(path) - 1] = '\0';

    ZERO_STRUCT(sunaddr);
    sunaddr.sun_family = AF_UNIX;
    strncpy(sunaddr.sun_path, path, sizeof(sunaddr.sun_path) - 1);

    /* If socket file doesn't exist, don't bother trying to connect with
       retry.  This is an attempt to make the system usable when the
       winbindd daemon is not running. */

    if (lstat(path, &st) == -1) {
        return -1;
    }

    /* Check permissions on unix socket file */
    
    if (!S_ISSOCK(st.st_mode) || (st.st_uid != 0)) {
        return -1;
    }

    /* Connect to socket */

    if ((established_socket = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        return -1;
    }

    if (connect(established_socket, (struct sockaddr *)&sunaddr, 
                sizeof(sunaddr)) == -1) {
        close_sock();
        return -1;
    }
        
    return established_socket;
}

/* Write data to winbindd socket with timeout */

int write_sock(void *buffer, int count)
{
    int result, nwritten;

    /* Open connection to winbind daemon */

 restart:

    if (open_pipe_sock() == -1) {
        return -1;
    }

    /* Write data to socket */

    nwritten = 0;

    while(nwritten < count) {
        struct timeval tv;
        fd_set r_fds;
        int selret;

        /* Catch pipe close on other end by checking if a read() call would 
           not block by calling select(). */

        FD_ZERO(&r_fds);
        FD_SET(established_socket, &r_fds);
        ZERO_STRUCT(tv);

        if ((selret = select(established_socket + 1, &r_fds, NULL, NULL, 
                             &tv)) == -1) {
            close_sock();
            return -1;                         /* Select error */
        }

        /* Write should be OK if fd not available for reading */

        if (!FD_ISSET(established_socket, &r_fds)) {

            /* Do the write */

            result = write(established_socket, (char *)buffer + nwritten, 
                           count - nwritten);

            if ((result == -1) || (result == 0)) {

                /* Write failed */
            
                close_sock();
                return -1;
            }

            nwritten += result;

        } else {

            /* Pipe has closed on remote end */

            close_sock();
            goto restart;
        }
    }
    
    return nwritten;
}

/* Read data from winbindd socket with timeout */

static int read_sock(void *buffer, int count)
{
    int result, nread;

    /* Read data from socket */

    nread = 0;

    while(nread < count) {

        result = read(established_socket, (char *)buffer + nread, 
                      count - nread);
        
        if ((result == -1) || (result == 0)) {

            /* Read failed.  I think the only useful thing we can do here 
               is just return -1 and fail since the transaction has failed
               half way through. */
            
            close_sock();
            return -1;
        }
        
        nread += result;
    }

    return result;
}

/* Read reply */

int read_reply(struct winbindd_response *response)
{
    int result1, result2;

    if (!response) {
        return -1;
    }

    /* Read fixed length response */

    if ((result1 = read_sock(response, sizeof(struct winbindd_response)))
         == -1) {

        return -1;
    }

    /* Read variable length response */

    if (response->length > sizeof(struct winbindd_response)) {
        int extra_data_len = response->length - 
            sizeof(struct winbindd_response);

        /* Mallocate memory for extra data */

        if (!(response->extra_data = malloc(extra_data_len))) {
            return -1;
        }

        if ((result2 = read_sock(response->extra_data, extra_data_len))
            == -1) {

            return -1;
        }
    }

    /* Return total amount of data read */

    return result1 + result2;
}

