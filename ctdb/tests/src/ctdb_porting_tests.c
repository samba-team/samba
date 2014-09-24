/*
   Test porting lib (common/system_*.c)

   Copyright (C) Mathieu Parent 2013

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

#include "includes.h"
#include "include/ctdb_private.h"
#include "system/filesys.h"
#include "popt.h"
#include "cmdline.h"

static struct {
	const char *socketname;
	const char *debuglevel;
	pid_t helper_pid;
	int socket;
	int successcount;
	int testcount;
} globals = {
	.socketname = "/tmp/test.sock"
};



/*
  Socket functions
*/
/*
  create a unix domain socket and bind it
  return a file descriptor open on the socket
*/
static int socket_server_create(void)
{
	struct sockaddr_un addr;

	globals.socket = socket(AF_UNIX, SOCK_STREAM, 0);
	if (globals.socket == -1) {
		DEBUG(DEBUG_CRIT,("Unable to create server socket: %s\n", strerror(errno)));
		return -1;
	}

	set_close_on_exec(globals.socket);
	//set_nonblocking(globals.socket);

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, globals.socketname, sizeof(addr.sun_path)-1);

	if (bind(globals.socket, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
		DEBUG(DEBUG_CRIT,("Unable to bind on socket '%s': %s\n", globals.socketname, strerror(errno)));
		goto failed;
	}

	if (chown(globals.socketname, geteuid(), getegid()) != 0 ||
		chmod(globals.socketname, 0700) != 0) {
		DEBUG(DEBUG_CRIT,("Unable to secure socket '%s': %s\n", globals.socketname, strerror(errno)));
		goto failed;
	}


	if (listen(globals.socket, 100) != 0) {
		DEBUG(DEBUG_CRIT,("Unable to listen on socket '%s': %s\n", globals.socketname, strerror(errno)));
		goto failed;
	}
	return 0;

failed:
	close(globals.socket);
	globals.socket = -1;
	return -1;
}

static int socket_server_wait_peer(void)
{
	struct sockaddr_un addr;
	socklen_t len;
	int fd;

	memset(&addr, 0, sizeof(addr));
	len = sizeof(addr);
	fd = accept(globals.socket, (struct sockaddr *)&addr, &len);
	if (fd == -1) {
		DEBUG(DEBUG_CRIT,("Unable to accept on ctdb socket '%s': %s\n", globals.socketname, strerror(errno)));
		return -1;
	}

	//set_nonblocking(fd);
	set_close_on_exec(fd);
	return fd;
}

static int socket_server_close(void)
{
	if (close(globals.socket) == -1) {
		DEBUG(DEBUG_CRIT,("Unable to close server socket: %s\n", strerror(errno)));
		return -1;
	}
	if (unlink(globals.socketname) == -1) {
		DEBUG(DEBUG_CRIT,("Unable to remove server socket: %s\n", strerror(errno)));
		return -1;
	}
	return 0;
}

static int socket_client_connect(void)
{
	struct sockaddr_un addr;
	int client = 0;

	client = socket(AF_UNIX, SOCK_STREAM, 0);
	if (client == -1) {
		DEBUG(DEBUG_CRIT,("Unable to create client socket: %s\n", strerror(errno)));
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, globals.socketname, sizeof(addr.sun_path)-1);
	if (connect(client, (struct sockaddr *)&addr, sizeof(addr))==-1) {
		DEBUG(DEBUG_CRIT,("Unable to connect to '%s': %s\n", globals.socketname, strerror(errno)));
		close(client);
		return -1;
	}

	return client;
}

static int socket_client_write(int client)
{
	if (sys_write(client, "\0", 1) == -1) {
		DEBUG(DEBUG_CRIT,("Unable to write to client socket: %s\n", strerror(errno)));
		return -1;
	}
	return 0;
}

static int socket_client_close(int client)
{
	if (close(client) == -1) {
		DEBUG(DEBUG_CRIT,("Unable to close client socket: %s\n", strerror(errno)));
		return -1;
	}
	return 0;
}

/*
  forked program
*/
static int fork_helper(void)
{
	pid_t pid;
	int i, client, max_rounds = 10;

	pid = fork();
	if (pid == -1) {
		DEBUG(DEBUG_CRIT,("Unable to fork: %s\n", strerror(errno)));
		return -1;
	}
	if (pid == 0) { // Child
		client = socket_client_connect();
		if (client < 0) {
			exit(1);
		}
		socket_client_write(client);
		for (i = 1 ; i <= max_rounds ; i++ ) {
			DEBUG(DEBUG_DEBUG,("Child process waiting ( %d/%d)\n", i, max_rounds));
			sleep(1);
		}
		socket_client_close(client);
		exit(0);
	} else {
		globals.helper_pid = pid;
	}
	return 0;
}

/*
  tests
*/
static int test_ctdb_sys_check_iface_exists(void)
{
	const char *fakename = "fake";
	bool test;
	globals.testcount++;
	test = ctdb_sys_check_iface_exists(fakename);
	if(test == true) {
		DEBUG(DEBUG_CRIT,("Test failed: Fake interface detected: %s\n", fakename));
		return -1;
	}
	DEBUG(DEBUG_INFO,("Test OK: Fake interface not detected: %s\n", fakename));
	globals.successcount++;
	return 0;
}

static int test_ctdb_get_peer_pid(void)
{
	int ret;
	int fd;
	pid_t peer_pid = 0;
	globals.testcount++;
	fd = socket_server_wait_peer();
	if (fd < 0) {
		return -1;
	}
	ret = ctdb_get_peer_pid(fd, &peer_pid);
	if (ret == -1) {
		DEBUG(DEBUG_CRIT,("Test failed: Unable to get peer process id\n"));
		close(fd);
		return -1;
	}
	if (peer_pid <= 0) {
		DEBUG(DEBUG_CRIT,("Test failed: Invalid peer process id: %d\n", peer_pid));
		close(fd);
		return -1;
	}
	DEBUG(DEBUG_INFO,("Test OK: Peer process id: %d\n", peer_pid));
	globals.successcount++;
	close(fd);
	return 0;
}

static int test_ctdb_get_process_name(void)
{
	char *process_name = NULL;
	globals.testcount++;
	process_name = ctdb_get_process_name(globals.helper_pid);
	if ((process_name == NULL) || !strcmp(process_name, "unknown")) {
		DEBUG(DEBUG_CRIT,("Test failed: Invalid process name of %d: %s\n", globals.helper_pid, process_name));
		free(process_name);
		return -1;
	}
	DEBUG(DEBUG_INFO,("Test OK: Name of PID=%d: %s\n", globals.helper_pid, process_name));
	globals.successcount++;
	free(process_name);
	return 0;
}

/*
  main program
*/
int main(int argc, const char *argv[])
{
	struct poptOption popt_options[] = {
		POPT_AUTOHELP
		{ "socket", 0, POPT_ARG_STRING, &globals.socketname, 0, "local socket name", "filename" },
		POPT_TABLEEND
	};
	int opt;
	const char **extra_argv;
	int extra_argc = 0;
	poptContext pc;

	DEBUGLEVEL = DEBUG_INFO;

	pc = poptGetContext(argv[0], argc, argv, popt_options, POPT_CONTEXT_KEEP_FIRST);

	while ((opt = poptGetNextOpt(pc)) != -1) {
		switch (opt) {
		default:
			fprintf(stderr, "Invalid option %s: %s\n",
				poptBadOption(pc, 0), poptStrerror(opt));
			exit(1);
		}
	}

	/* setup the remaining options for the main program to use */
	extra_argv = poptGetArgs(pc);
	if (extra_argv) {
		extra_argv++;
		while (extra_argv[extra_argc]) extra_argc++;
	}

	if (globals.socketname == NULL) {
		DEBUG(DEBUG_CRIT,("Socket name is undefined\n"));
		exit(1);
	}
	if (socket_server_create()) {
		DEBUG(DEBUG_CRIT,("Socket error: exiting\n"));
		exit(1);
	}
	if (fork_helper()) {
		DEBUG(DEBUG_CRIT,("Forking error: exiting\n"));
		exit(1);
	}
	/* FIXME: Test tcp_checksum6, tcp_checksum */
	/* FIXME: Test ctdb_sys_send_arp, ctdb_sys_send_tcp */
	/* FIXME: Test ctdb_sys_{open,close}_capture_socket, ctdb_sys_read_tcp_packet */
	test_ctdb_sys_check_iface_exists();
	test_ctdb_get_peer_pid();
	test_ctdb_get_process_name();
	/* FIXME: Test ctdb_get_lock_info, ctdb_get_blocker_pid*/

	socket_server_close();

	DEBUG(DEBUG_INFO,("%d/%d tests successfull\n", globals.successcount, globals.testcount));
	return 0;
}
