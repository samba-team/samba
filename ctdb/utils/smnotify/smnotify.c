/* 
   simple smnotify tool

   Copyright (C) Ronnie Sahlberg 2007

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, see <http://www.gnu.org/licenses/>.
*/
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include "smnotify.h"
#include "popt.h"

static char *client       = NULL;
static const char *ip     = NULL;
static char *server = NULL;
static int stateval       = 0;
static int clientport     = 0;
static int sendport       = 0;

static void usage(void)
{
	exit(0);
}

static int create_socket(const char *addr, int port)
{
	int s;
        struct sockaddr_in sock_in;

	s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (s == -1) {
		printf("Failed to open local socket\n");
		exit(10);
	}

	bzero(&sock_in, sizeof(sock_in));
	sock_in.sin_family = AF_INET;
	sock_in.sin_port   = htons(port);
	inet_aton(addr, &sock_in.sin_addr);
	if (bind(s, (struct sockaddr *)&sock_in, sizeof(sock_in)) == -1) {
		printf("Failed to bind to local socket\n");
		exit(10);
	}

	return s;
}

int main(int argc, const char *argv[])
{
	struct poptOption popt_options[] = {
		POPT_AUTOHELP
		{ "client", 'c', POPT_ARG_STRING, &client, 0, "remote client to send the notify to", "hostname/ip" },
		{ "clientport", 0, POPT_ARG_INT, &clientport, 0, "clientport", "integer" },
		{ "ip", 'i', POPT_ARG_STRING, &ip, 0, "local ip address to send the notification from", "ip" },
		{ "sendport", 0, POPT_ARG_INT, &sendport, 0, "port to send the notify from", "integer" },
		{ "server", 's', POPT_ARG_STRING, &server, 0, "servername to use in the notification", "hostname/ip" },
		{ "stateval", 0, POPT_ARG_INT, &stateval, 0, "stateval", "integer" },
		POPT_TABLEEND
	};
	int opt;
	poptContext pc;
	CLIENT *clnt;
	int s;
        struct sockaddr_in sock_cl;
	struct timeval w;
	struct status st;

	pc = poptGetContext(argv[0], argc, argv, popt_options, POPT_CONTEXT_KEEP_FIRST);

	while ((opt = poptGetNextOpt(pc)) != -1) {
		switch (opt) {
		default:
			fprintf(stderr, "Invalid option %s: %s\n", 
				poptBadOption(pc, 0), poptStrerror(opt));
			exit(1);
		}
	}

	if (client == NULL) {
		printf("ERROR: client not specified\n");
		usage();
	}

	if (ip == NULL) {
		printf("ERROR: ip not specified\n");
		usage();
	}

	if (server == NULL) {
		printf("ERROR: server not specified\n");
		usage();
	}

	if (stateval == 0) {
		printf("ERROR: stateval not specified\n");
		usage();
	}


	/* Since we want to control from which address these packets are
	   sent we must create the socket ourself and use low-level rpc
	   calls.
	*/
	s = create_socket(ip, sendport);

	/* only wait for at most 3 seconds before giving up */
	alarm(3);

	/* Setup a sockaddr_in for the client we want to notify */
	bzero(&sock_cl, sizeof(sock_cl));
	sock_cl.sin_family = AF_INET;
	sock_cl.sin_port   = htons(clientport);
	inet_aton(client, &sock_cl.sin_addr);

	w.tv_sec = 1;
	w.tv_usec= 0;

	clnt = clntudp_create(&sock_cl, 100024, 1, w, &s);
	if (clnt == NULL) {
		printf("ERROR: failed to connect to client\n");
		exit(10);
	}

	/* we don't want to wait for any reply */
	w.tv_sec = 0;
	w.tv_usec = 0;
	clnt_control(clnt, CLSET_TIMEOUT, (char *)&w);

	st.mon_name=server;
	st.state=stateval;
	sm_notify_1(&st, clnt);

	return 0;
}
