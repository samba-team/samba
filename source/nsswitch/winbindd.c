/* 
   Unix SMB/Netbios implementation.
   Version 2.0

   Winbind daemon for ntdom nss module

   Copyright (C) Tim Potter 2000
   
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

#include <stdio.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "includes.h"

/* List of all connected clients */

static struct winbindd_state *client_list;

/*
 * Signal handlers
 */

static void termination_handler(int signum)
{
    /* Remove socket file */

    unlink(WINBINDD_SOCKET_DIR "/" WINBINDD_SOCKET_NAME);

    exit(0);
}

static BOOL print_client_info;

static void siguser1_handler(int signum)
{
    print_client_info = True;
}

static BOOL flush_cache;

static void sighup_handler(int signum)
{
    flush_cache = True;
}

/* Create winbindd socket */

static int create_sock(void)
{
    struct sockaddr_un sunaddr;
    struct stat st;
    int sock;
    mode_t old_umask;
    char *path = WINBINDD_SOCKET_DIR "/" WINBINDD_SOCKET_NAME;

    /* Create the socket directory or reuse the existing one */

    if ((lstat(WINBINDD_SOCKET_DIR, &st) == -1) && (errno != ENOENT)) {
        DEBUG(0, ("lstat failed on socket directory %s: %s\n",
                  WINBINDD_SOCKET_DIR, sys_errlist[errno]));
        return -1;
    }

    if (errno == ENOENT) {

        /* Create directory */

        if (mkdir(WINBINDD_SOCKET_DIR, 0755) == -1) {
            DEBUG(0, ("error creating socket directory %s: %s\n",
                      WINBINDD_SOCKET_DIR, sys_errlist[errno]));
            return -1;
        }

    } else {

        /* Check ownership and permission on existing directory */

        if (!S_ISDIR(st.st_mode)) {
            DEBUG(0, ("socket directory %s isn't a directory\n",
                      WINBINDD_SOCKET_DIR));
            return -1;
        }

        if ((st.st_uid != 0) || ((st.st_mode & 0777) != 0755)) {
            DEBUG(0, ("invalid permissions on socket directory %s\n",
                      WINBINDD_SOCKET_DIR));
            return -1;
        }
    }

    /* Create the socket file */

    old_umask = umask(0);

    sock = socket(AF_UNIX, SOCK_STREAM, 0);
    
    if (sock == -1) {
        perror("socket");
        return -1;
    }
    
    unlink(path);
    memset(&sunaddr, 0, sizeof(sunaddr));
    sunaddr.sun_family = AF_UNIX;
    strncpy(sunaddr.sun_path, path,
            sizeof(sunaddr.sun_path));
    
    if (bind(sock, (struct sockaddr *)&sunaddr, sizeof(sunaddr)) == -1) {
        DEBUG(0, ("bind failed on winbind socket %s: %s\n",
                  path,
                  sys_errlist[errno]));
        close(sock);
        return -1;
    }
    
    if (listen(sock, 5) == -1) {
        DEBUG(0, ("listen failed on winbind socket %s: %s\n",
                  path,
                  sys_errlist[errno]));
        close(sock);
        return -1;
    }
    
    umask(old_umask);
    
    /* Success! */
    
    return sock;
}


static void process_request(struct winbindd_state *state)
{
    /* Process command */

    state->response.result = WINBINDD_ERROR;

    switch(state->request.cmd) {
        
        /* User functions */
        
    case WINBINDD_GETPWNAM_FROM_USER: 
        state->response.result = winbindd_getpwnam_from_user(state);
        break;
        
    case WINBINDD_GETPWNAM_FROM_UID:
        state->response.result = winbindd_getpwnam_from_uid(state);
        break;
        
    case WINBINDD_SETPWENT:
        state->response.result = winbindd_setpwent(state);
        break;
        
    case WINBINDD_ENDPWENT:
        state->response.result = winbindd_endpwent(state);
        break;
        
    case WINBINDD_GETPWENT:
        state->response.result = winbindd_getpwent(state);
        break;
        
        /* Group functions */
        
    case WINBINDD_GETGRNAM_FROM_GROUP:
        state->response.result = winbindd_getgrnam_from_group(state);
        break;
        
    case WINBINDD_GETGRNAM_FROM_GID:
        state->response.result = winbindd_getgrnam_from_gid(state);
        break;
        
    case WINBINDD_SETGRENT:
        state->response.result = winbindd_setgrent(state);
        break;
        
    case WINBINDD_ENDGRENT:
        state->response.result = winbindd_endgrent(state);
        break;
        
    case WINBINDD_GETGRENT:
        state->response.result = winbindd_getgrent(state);
        break;
        
        /* Oops */
        
    default:
        DEBUG(0, ("oops - unknown winbindd command %d\n", state->request.cmd));
        break;
    }
}

/* Process a new connection by adding it to the client connection list */

static void new_connection(int accept_sock)
{
    struct sockaddr_un sunaddr;
    struct winbindd_state *state;
    int len, sock;
    
    /* Accept connection */
    
    len = sizeof(sunaddr);
    if ((sock = accept(accept_sock, (struct sockaddr *)&sunaddr, &len)) 
        == -1) {
        
        return;
    }

    fprintf(stderr, "accepted socket %d\n", sock);

    /* Create new connection structure */

    if ((state = (struct winbindd_state *)malloc(sizeof(*state))) == NULL) {
        return;
    }

    ZERO_STRUCTP(state);
    state->sock = sock;

    /* Add to connection list */

    DLIST_ADD(client_list, state);
}

/* Remove a client connection from client connection list */

static void remove_client(struct winbindd_state *state)
{
    /* It's a dead client - hold a funeral */

    close(state->sock);
//    free_state_info(state);
    DLIST_REMOVE(client_list, state);
    free(state);
}

/* Process a complete received packet from a client */

static void process_packet(struct winbindd_state *state)
{
    /* Process request */

    process_request(state);

    /* Update client state */

    state->read_buf_len = 0;
    state->write_buf_len = sizeof(state->response);
}

/* Read some data from a client connection */

static void client_read(struct winbindd_state *state)
{
    int n;
    
    /* Read data */

    n = read(state->sock, state->read_buf_len + (char *)&state->request, 
             sizeof(state->request) - state->read_buf_len);

    fprintf(stderr, "read returned %d on sock %d\n", n, state->sock);

    /* Read failed, kill client */

    if ((n == -1) || (n == 0)) {
        fprintf(stderr, "finished reading, n = %d\n", n);
        state->finished = True;
        return;
    }

    /* Update client state */

    state->read_buf_len += n;
}

/* Write some data to a client connection */

static void client_write(struct winbindd_state *state)
{
    int n;

    /* Write data */

    n = write(state->sock, (sizeof(state->response) - state->write_buf_len) +
              (char *)&state->response,
              state->write_buf_len);

    fprintf(stderr, "write returned %d on sock %d\n", n, state->sock);

    /* Write failed, kill cilent */

    if (n == -1 || n == 0) {
        fprintf(stderr, "finished writing\n");
        state->finished = True;
        return;
    }

    /* Update client state */
    
    state->write_buf_len -= n;
}

/* Process incoming clients on accept_sock.  We use a tricky non-blocking,
   non-forking, non-threaded model which allows us to handle many
   simultaneous connections while remaining impervious to many denial of
   service attacks. */

static void process_loop(int accept_sock)
{
    /* We'll be doing this a lot */

    while (1) {
        struct winbindd_state *state;
        fd_set r_fds, w_fds;
        int maxfd = accept_sock, selret;

        /* Initialise fd lists for select() */

        FD_ZERO(&r_fds);
        FD_ZERO(&w_fds);
        FD_SET(accept_sock, &r_fds);

        /* Set up client readers and writers */

        state = client_list;

        while (state) {

            /* Dispose of client connection if it is marked as finished */ 

            if (state->finished) {
                struct winbindd_state *next = state->next;

                fprintf(stderr, "removing client sock %d\n", state->sock);
                remove_client(state);
                state = next;
                continue;
            }

            /* Select requires we know the highest fd used */

            if (state->sock > maxfd) maxfd = state->sock;

            /* Add fd for reading */

            if (state->read_buf_len != sizeof(state->request)) {

                fprintf(stderr, "adding sock %d for reading\n", state->sock);
                FD_SET(state->sock, &r_fds);
            }

            /* Add fd for writing */

            if (state->write_buf_len) {

                fprintf(stderr, "adding sock %d for writing\n", state->sock);
                FD_SET(state->sock, &w_fds);
            }

            state = state->next;
        }

        /* Check signal handling */

        if (flush_cache) {
            fprintf(stderr, "flush cache request\n");
            flush_cache = False;
        }

        if (print_client_info) {
            fprintf(stderr, "print client info requet\n");
            print_client_info = False;
        }

        /* Call select */
        
        fprintf(stderr, "calling select\n");
        selret = select(maxfd + 1, &r_fds, &w_fds, NULL, NULL);
        
        if (selret == -1 || selret == 0) {

            /* Select error, something is badly wrong */

            exit(2);
            DEBUG(0, ("select returned %d", selret));
            return;
        }

        /* Create a new connection if accept_sock readable */

        if (FD_ISSET(accept_sock, &r_fds)) {
            new_connection(accept_sock);
        }

        /* Process activity on client connections */

        for (state = client_list; state ; state = state->next) {

            /* Data available for reading */

            if (FD_ISSET(state->sock, &r_fds)) {

                /* Read data */

                client_read(state);

                /* A request packet might be complete */

                if (state->read_buf_len == sizeof(state->request)) {
                    process_packet(state);
                }
            }

            /* Data available for writing */

            if (FD_ISSET(state->sock, &w_fds)) {
                client_write(state);
            }
        }
    }
}

/* Main function */

int main(int argc, char **argv)
{
    extern fstring global_myname;
    extern pstring debugf;
    int accept_sock;

    /* Initialise samba/rpc client stuff */

    setup_logging("winbindd", True); /* XXX change to false for daemon log */
    slprintf(debugf, sizeof(debugf), "%s/log.winbindd", LOGFILEBASE);
    reopen_logs();

    if (!*global_myname) {
        char *p;

        fstrcpy(global_myname, myhostname());
        p = strchr(global_myname, '.');
        if (p) {
            *p = 0;
        }
    }

    TimeInit();
    charset_initialise();
    codepage_initialise(lp_client_code_page());

    if (!lp_load(CONFIGFILE, True, False, False)) {
        fprintf(stderr, "error opening config file\n");
        exit(1);
    }

    pwdb_initialise(False);

    if (!winbindd_param_init()) {
        return 1;
    }

    /* Setup signal handlers */

    signal(SIGINT, termination_handler);
    signal(SIGQUIT, termination_handler);
    signal(SIGTERM, termination_handler);
    signal(SIGPIPE, SIG_IGN);
    signal(SIGUSR1, siguser1_handler);
    signal(SIGHUP, sighup_handler);

    /* Create UNIX domain socket */

    if ((accept_sock = create_sock()) == -1) {
        DEBUG(0, ("failed to create socket\n"));
        return 1;
    }

    /* Loop waiting for requests */

    process_loop(accept_sock);

    return 0;
}
