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

#include "winbindd.h"

/* List of all connected clients */

static struct winbindd_cli_state *client_list;
static int num_clients;

/* Reload configuration */

static BOOL reload_services_file(void)
{
        pstring servicesf = CONFIGFILE;
	BOOL ret;

	reopen_logs();
	ret = lp_load(servicesf,False,False,True);

	reopen_logs();
	load_interfaces();

	return(ret);
}

void winbindd_dump_status(void)
{
    struct winbindd_cli_state *tmp;

    DEBUG(0, ("Global status for winbindd:\n"));

    /* Print client state information */
    
    DEBUG(0, ("\t%d clients currently active\n", num_clients));

    if (DEBUGLEVEL >= 2) {
        DEBUG(2, ("\tclient list:\n"));
        for(tmp = client_list; tmp; tmp = tmp->next) {
            DEBUG(2, ("\t\tpid %d, sock %d, rbl %d, wbl %d\n",
                      tmp->pid, tmp->sock, tmp->read_buf_len, 
                      tmp->write_buf_len));
        }
    }
}

/* Print winbindd status to log file */

static void do_print_winbindd_status(void)
{
    winbindd_dump_status();
    winbindd_idmap_dump_status();
    winbindd_cache_dump_status();
}

/* Flush client cache */

static void do_flush_caches(void)
{
    /* Clear cached user and group enumation info */

    winbindd_flush_cache();
}

/* Handle the signal by unlinking socket and exiting */

static void termination_handler(int signum)
{
    pstring path;

    /* Remove socket file */

    slprintf(path, sizeof(path), "%s/%s", 
	     WINBINDD_SOCKET_DIR, WINBINDD_SOCKET_NAME);
    unlink(path);

    exit(0);
}

static BOOL print_winbindd_status;

static void sigusr1_handler(int signum)
{
    BlockSignals(True, SIGUSR1);
    print_winbindd_status = True;
    BlockSignals(False, SIGUSR1);
}

static BOOL do_sighup;

static void sighup_handler(int signum)
{
    BlockSignals(True, SIGHUP);
    do_sighup = True;
    BlockSignals(False, SIGHUP);
}

/* Create winbindd socket */

static int create_sock(void)
{
    struct sockaddr_un sunaddr;
    struct stat st;
    int sock;
    mode_t old_umask;
    pstring path;

    /* Create the socket directory or reuse the existing one */

    if (lstat(WINBINDD_SOCKET_DIR, &st) == -1) {

        if (errno == ENOENT) {

            /* Create directory */

            if (mkdir(WINBINDD_SOCKET_DIR, 0755) == -1) {
                DEBUG(0, ("error creating socket directory %s: %s\n",
                          WINBINDD_SOCKET_DIR, sys_errlist[errno]));
                return -1;
            }

        } else {

            DEBUG(0, ("lstat failed on socket directory %s: %s\n",
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

    slprintf(path, sizeof(path), "%s/%s", 
	     WINBINDD_SOCKET_DIR, WINBINDD_SOCKET_NAME);

    unlink(path);
    memset(&sunaddr, 0, sizeof(sunaddr));
    sunaddr.sun_family = AF_UNIX;
    safe_strcpy(sunaddr.sun_path, path, sizeof(sunaddr.sun_path)-1);
    
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

struct dispatch_table {
	enum winbindd_cmd cmd;
	enum winbindd_result (*fn)(struct winbindd_cli_state *state);
};

static struct dispatch_table dispatch_table[] = {
	
	/* User functions */

	{ WINBINDD_GETPWNAM_FROM_USER, winbindd_getpwnam_from_user },
	{ WINBINDD_GETPWNAM_FROM_UID, winbindd_getpwnam_from_uid },
	{ WINBINDD_SETPWENT, winbindd_setpwent },
	{ WINBINDD_ENDPWENT, winbindd_endpwent },
	{ WINBINDD_GETPWENT, winbindd_getpwent },

	/* Group functions */

	{ WINBINDD_GETGRNAM_FROM_GROUP, winbindd_getgrnam_from_group },
	{ WINBINDD_GETGRNAM_FROM_GID, winbindd_getgrnam_from_gid },
	{ WINBINDD_SETGRENT, winbindd_setgrent },
	{ WINBINDD_ENDGRENT, winbindd_endgrent },
	{ WINBINDD_GETGRENT, winbindd_getgrent },

	/* PAM auth functions */

	{ WINBINDD_PAM_AUTH, winbindd_pam_auth },
	{ WINBINDD_PAM_CHAUTHTOK, winbindd_pam_chauthtok },

	/* Enumeration functions */

        { WINBINDD_LIST_USERS, winbindd_list_users },
        { WINBINDD_LIST_GROUPS, winbindd_list_groups },
	{ WINBINDD_LIST_TRUSTDOM, winbindd_list_trusted_domains },

	/* SID related functions */

	{ WINBINDD_LOOKUPSID, winbindd_lookupsid },
	{ WINBINDD_LOOKUPNAME, winbindd_lookupname },

	/* S*RS related functions */

	{ WINBINDD_SID_TO_UID, winbindd_sid_to_uid },
	{ WINBINDD_SID_TO_GID, winbindd_sid_to_gid },
	{ WINBINDD_GID_TO_SID, winbindd_gid_to_sid },
	{ WINBINDD_UID_TO_SID, winbindd_uid_to_sid },

	/* Miscellaneous */

	{ WINBINDD_CHECK_MACHACC, winbindd_check_machine_acct },

	/* End of list */

	{ WINBINDD_NUM_CMDS, NULL }
};

static void process_request(struct winbindd_cli_state *state)
{
	struct dispatch_table *table = dispatch_table;

	/* Free response data - we may be interrupted and receive another
	   command before being able to send this data off. */

	safe_free(state->response.extra_data);  

	ZERO_STRUCT(state->response);

	state->response.result = WINBINDD_ERROR;
	state->response.length = sizeof(struct winbindd_response);

	/* Process command */

	DEBUG(3,("[%5d]: %s\n", state->pid,
		 winbindd_cmd_to_string(state->request.cmd)));

	if (!server_state.lsa_handle_open) return;

	for (table = dispatch_table; table->fn; table++) {
		if (state->request.cmd == table->cmd) {
			state->response.result = table->fn(state);
			break;
		}
	}
}

/* Process a new connection by adding it to the client connection list */

static void new_connection(int accept_sock)
{
    struct sockaddr_un sunaddr;
    struct winbindd_cli_state *state;
    int len, sock;
    
    /* Accept connection */
    
    len = sizeof(sunaddr);
    if ((sock = accept(accept_sock, (struct sockaddr *)&sunaddr, &len)) 
        == -1) {
        
        return;
    }

    DEBUG(6,("accepted socket %d\n", sock));

    /* Create new connection structure */

    if ((state = (struct winbindd_cli_state *)
         malloc(sizeof(*state))) == NULL) {

        return;
    }

    ZERO_STRUCTP(state);
    state->sock = sock;

    /* Add to connection list */

    DLIST_ADD(client_list, state);
    num_clients++;
}

/* Remove a client connection from client connection list */

static void remove_client(struct winbindd_cli_state *state)
{
	/* It's a dead client - hold a funeral */
	
	if (state != NULL) {
		
		/* Close socket */
		
		close(state->sock);
		
		/* Free any getent state */
		
		free_getent_state(state->getpwent_state);
		free_getent_state(state->getgrent_state);
		
		/* We may have some extra data that was not freed if the
		   client was killed unexpectedly */

		safe_free(state->response.extra_data);
		
		/* Remove from list and free */
		
		DLIST_REMOVE(client_list, state);
		free(state);
		num_clients--;
	}
}

/* Process a complete received packet from a client */

static void process_packet(struct winbindd_cli_state *state)
{
	/* Process request */
	
	state->pid = state->request.pid;
	
	process_request(state);

	/* Update client state */
	
	state->read_buf_len = 0;
	state->write_buf_len = sizeof(struct winbindd_response);
}

/* Read some data from a client connection */

static void client_read(struct winbindd_cli_state *state)
{
	int n;
    
	/* Read data */

	n = read(state->sock, state->read_buf_len + (char *)&state->request, 
		 sizeof(state->request) - state->read_buf_len);
	
	/* Read failed, kill client */
	
	if (n == -1 || n == 0) {
		DEBUG(5,("read failed on sock %d, pid %d: %s\n",
			 state->sock, state->pid, 
			 (n == -1) ? sys_errlist[errno] : "EOF"));
		
		state->finished = True;
		return;
	}
	
	/* Update client state */
	
	state->read_buf_len += n;
}

/* Write some data to a client connection */

static void client_write(struct winbindd_cli_state *state)
{
	char *data;
	int num_written;
	
	/* Write some data */
	
	if (!state->write_extra_data) {

		/* Write response structure */
		
		data = (char *)&state->response + sizeof(state->response) - 
			state->write_buf_len;

	} else {

		/* Write extra data */
		
		data = (char *)state->response.extra_data + 
			state->response.length - 
			sizeof(struct winbindd_response) - 
			state->write_buf_len;
	}
	
	num_written = write(state->sock, data, state->write_buf_len);
	
	/* Write failed, kill cilent */
	
	if (num_written == -1 || num_written == 0) {
		
		DEBUG(3,("write failed on sock %d, pid %d: %s\n",
			 state->sock, state->pid, 
			 (num_written == -1) ? sys_errlist[errno] : "EOF"));
		
		state->finished = True;

		safe_free(state->response.extra_data);
		state->response.extra_data = NULL;

		return;
	}
	
	/* Update client state */
	
	state->write_buf_len -= num_written;
	
	/* Have we written all data? */
	
	if (state->write_buf_len == 0) {
		
		/* Take care of extra data */
		
		if (state->write_extra_data) {

			safe_free(state->response.extra_data);
			state->response.extra_data = NULL;

			state->write_extra_data = False;

		} else if (state->response.length > 
			   sizeof(struct winbindd_response)) {
			
			/* Start writing extra data */

			state->write_buf_len = 
				state->response.length -
				sizeof(struct winbindd_response);
			
			state->write_extra_data = True;
		}
	}
}

/* Process incoming clients on accept_sock.  We use a tricky non-blocking,
   non-forking, non-threaded model which allows us to handle many
   simultaneous connections while remaining impervious to many denial of
   service attacks. */

static void process_loop(int accept_sock)
{
	/* We'll be doing this a lot */

	while (1) {
		struct winbindd_cli_state *state;
		fd_set r_fds, w_fds;
		int maxfd = accept_sock, selret;
		struct timeval timeout;

		/* Free up temporary memory */

		lp_talloc_free();

		/* Do any connection establishment that is needed */

		establish_connections(False);	    /* Honour timeout */

		/* Initialise fd lists for select() */

		FD_ZERO(&r_fds);
		FD_ZERO(&w_fds);
		FD_SET(accept_sock, &r_fds);

		timeout.tv_sec = WINBINDD_ESTABLISH_LOOP;
		timeout.tv_usec = 0;

		/* Set up client readers and writers */

		state = client_list;

		while (state) {

			/* Dispose of client connection if it is marked as 
			   finished */ 

			if (state->finished) {
				struct winbindd_cli_state *next = state->next;

				remove_client(state);
				state = next;
				continue;
			}

			/* Select requires we know the highest fd used */

			if (state->sock > maxfd) maxfd = state->sock;

			/* Add fd for reading */

			if (state->read_buf_len != sizeof(state->request)) {
				FD_SET(state->sock, &r_fds);
			}

			/* Add fd for writing */

			if (state->write_buf_len) {
				FD_SET(state->sock, &w_fds);
			}

			state = state->next;
		}

		/* Check signal handling things */

		if (do_sighup) {

			/* Flush winbindd cache */

			do_flush_caches();
			reload_services_file();

			/* Close and re-open all connections.  This will also
			   refresh the trusted domains list */

			winbindd_kill_connections();
			establish_connections(True); /* Force re-establish */

			do_sighup = False;
		}

		if (print_winbindd_status) {
			do_print_winbindd_status();
			print_winbindd_status = False;
		}

		/* Call select */
        
		selret = select(maxfd + 1, &r_fds, &w_fds, NULL, &timeout);

		if (selret == 0) continue;

		if ((selret == -1 && errno != EINTR) || selret == 0) {

			/* Select error, something is badly wrong */

			perror("select");
			exit(1);
		}

		/* Create a new connection if accept_sock readable */

		if (selret > 0) {

			if (FD_ISSET(accept_sock, &r_fds)) {
				new_connection(accept_sock);
			}
            
			/* Process activity on client connections */
            
			for (state = client_list; state; state = state->next) {
                
				/* Data available for reading */
                
				if (FD_ISSET(state->sock, &r_fds)) {
                    
					/* Read data */
                    
					client_read(state);
                    
					/* A request packet might be 
					   complete */
                    
					if (state->read_buf_len == 
					    sizeof(state->request)) {
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
}

/* Main function */

struct winbindd_state server_state;   /* Server state information */

int main(int argc, char **argv)
{
	extern pstring global_myname;
	extern pstring debugf;
	int accept_sock;
	BOOL interactive = False;
	int opt, new_debuglevel = -1;

	/* Set environment variable so we don't recursively call ourselves.
	   This may also be useful interactively. */

	setenv(WINBINDD_DONT_ENV, "1", 1);

	/* Initialise samba/rpc client stuff */

	while ((opt = getopt(argc, argv, "id:")) != EOF) {
		switch (opt) {
		case 'i':
			interactive = True;
			break;
		case 'd':
			new_debuglevel = atoi(optarg);
			break;
		default:
			printf("Unknown option %c\n", (char)opt);
			exit(1);
		}
	}

	slprintf(debugf, sizeof(debugf), "%s/log.winbindd", LOGFILEBASE);
	setup_logging("winbindd", interactive);
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

	if (!lp_load(CONFIGFILE, True, False, False)) {
		DEBUG(0, ("error opening config file\n"));
		exit(1);
	}

	if (new_debuglevel != -1) {
		DEBUGLEVEL = new_debuglevel;
	}

	codepage_initialise(lp_client_code_page());

	if (!interactive) {
		become_daemon();
	}

	load_interfaces();

	secrets_init();

	ZERO_STRUCT(server_state);

	/* Winbind daemon initialisation */
	if (!winbindd_param_init()) {
		return 1;
	}

	if (!winbindd_idmap_init()) {
		return 1;
	}

	winbindd_cache_init();

	/* Setup signal handlers */
	
	CatchSignal(SIGINT, termination_handler);      /* Exit on these sigs */
	CatchSignal(SIGQUIT, termination_handler);
	CatchSignal(SIGTERM, termination_handler);

	CatchSignal(SIGPIPE, SIG_IGN);                 /* Ignore sigpipe */

	CatchSignal(SIGUSR1, sigusr1_handler);         /* Debugging sigs */
	CatchSignal(SIGHUP, sighup_handler);

	/* Create UNIX domain socket */
	
	if ((accept_sock = create_sock()) == -1) {
		DEBUG(0, ("failed to create socket\n"));
		return 1;
	}

	/* Loop waiting for requests */

	process_loop(accept_sock);

	return 0;
}
