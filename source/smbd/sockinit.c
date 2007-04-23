/* 
   Unix SMB/CIFS implementation.

   Copyright (C) Andrew Tridgell		1992-1998
   Copyright (C) James Peach			2007
   
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

#include "includes.h"
#include "smb_launchd.h"

extern pstring user_socket_options;

static int init_sockets_smbd(const char *smb_ports, int listenset[FD_SETSIZE])
{
	int num_interfaces = iface_count();
	char * ports;
	int num_sockets = 0;
	int i, s;

	/* use a reasonable default set of ports - listing on 445 and 139 */
	if (!smb_ports) {
		ports = lp_smb_ports();
		if (!ports || !*ports) {
			ports = smb_xstrdup(SMB_PORTS);
		} else {
			ports = smb_xstrdup(ports);
		}
	} else {
		ports = smb_xstrdup(smb_ports);
	}

	if (lp_interfaces() && lp_bind_interfaces_only()) {
		/* We have been given an interfaces line, and been 
		   told to only bind to those interfaces. Create a
		   socket per interface and bind to only these.
		*/
		
		/* Now open a listen socket for each of the
		   interfaces. */
		for(i = 0; i < num_interfaces; i++) {
			struct in_addr *ifip = iface_n_ip(i);
			fstring tok;
			const char *ptr;

			if(ifip == NULL) {
				DEBUG(0,("init_sockets_smbd: interface %d has NULL IP address !\n", i));
				continue;
			}

			for (ptr=ports; next_token(&ptr, tok, " \t,", sizeof(tok)); ) {
				unsigned port = atoi(tok);
				if (port == 0) {
					continue;
				}
				s = listenset[num_sockets] = open_socket_in(SOCK_STREAM, port, 0, ifip->s_addr, True);
				if(s == -1)
					return 0;

				/* ready to listen */
				set_socket_options(s,"SO_KEEPALIVE"); 
				set_socket_options(s,user_socket_options);
     
				/* Set server socket to non-blocking for the accept. */
				set_blocking(s,False); 
 
				if (listen(s, SMBD_LISTEN_BACKLOG) == -1) {
					DEBUG(0,("listen: %s\n",strerror(errno)));
					close(s);
					return 0;
				}

				num_sockets++;
				if (num_sockets >= FD_SETSIZE) {
					DEBUG(0,("init_sockets_smbd: Too many sockets to bind to\n"));
					return 0;
				}
			}
		}
	} else {
		/* Just bind to 0.0.0.0 - accept connections
		   from anywhere. */

		fstring tok;
		const char *ptr;

		num_interfaces = 1;
		
		for (ptr=ports; next_token(&ptr, tok, " \t,", sizeof(tok)); ) {
			unsigned port = atoi(tok);
			if (port == 0) continue;
			/* open an incoming socket */
			s = open_socket_in(SOCK_STREAM, port, 0,
					   interpret_addr(lp_socket_address()),True);
			if (s == -1)
				return 0;
		
			/* ready to listen */
			set_socket_options(s,"SO_KEEPALIVE"); 
			set_socket_options(s,user_socket_options);
			
			/* Set server socket to non-blocking for the accept. */
			set_blocking(s,False); 
 
			if (listen(s, SMBD_LISTEN_BACKLOG) == -1) {
				DEBUG(0,("init_sockets_smbd: listen: %s\n",
					 strerror(errno)));
				close(s);
				return 0;
			}

			listenset[num_sockets] = s;
			num_sockets++;

			if (num_sockets >= FD_SETSIZE) {
				DEBUG(0,("init_sockets_smbd: Too many sockets to bind to\n"));
				return 0;
			}
		}
	} 

	SAFE_FREE(ports);
	return num_sockets;
}

static int init_sockets_launchd(const struct smb_launch_info *linfo,
				const char * smb_ports,
				int listenset[FD_SETSIZE])
{
	int num_sockets;
	int i;

	/* The launchd service configuration does not have to provide sockets,
	 * even though it's basically useless without it.
	 */
	if (!linfo->num_sockets) {
		return init_sockets_smbd(smb_ports, listenset);
	}

	/* Make sure we don't get more sockets than we can handle. */
	num_sockets = MIN(FD_SETSIZE, linfo->num_sockets);
	memcpy(listenset, linfo->socket_list, num_sockets * sizeof(int));

	/* Get the sockets ready. This could be hoisted into
	 * open_sockets_smbd(), but the order of socket operations might
	 * matter for some platforms, so this approach seems less risky.
	 *	--jpeach
	 */
	for (i = 0; i < num_sockets; ++i) {
		set_socket_options(listenset[i], "SO_KEEPALIVE");
		set_socket_options(listenset[i], user_socket_options);

		/* Set server socket to non-blocking for the accept. */
		set_blocking(listenset[i], False);
	}

	return num_sockets;
}

/* This function is responsible for opening (or retrieving) all the sockets we
 * smbd will be listening on. It should apply all the configured socket options
 * and return the number of valid sockets in listenset.
 */
int smbd_sockinit(const char *cmdline_ports, int listenset[FD_SETSIZE],
			struct timeval *idle)
{
	int num_sockets;
	struct smb_launch_info linfo;

	ZERO_STRUCTP(idle);

	if (smb_launchd_checkin(&linfo)) {
		/* We are running under launchd and launchd has
		 * opened some sockets for us.
		 */
		num_sockets = init_sockets_launchd(&linfo,
					    cmdline_ports,
					    listenset);
		idle->tv_sec = linfo.idle_timeout_secs;
		smb_launchd_checkout(&linfo);
	} else {
		num_sockets = init_sockets_smbd(cmdline_ports,
					    listenset);
	}

	return num_sockets;
}

