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

#include "replace.h"
#include "system/filesys.h"
#include "system/network.h"

#include <popt.h>
#include <talloc.h>
#include <tevent.h>
#include <tdb.h>
#include <assert.h>

#include "lib/util/debug.h"
#include "lib/util/blocking.h"

#include "protocol/protocol.h"
#include "common/system.h"
#include "common/logging.h"


static struct {
	const char *socketname;
	const char *debuglevel;
	pid_t helper_pid;
	int socket;
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
	int ret;

	globals.socket = socket(AF_UNIX, SOCK_STREAM, 0);
	assert(globals.socket != -1);

	set_close_on_exec(globals.socket);
	//set_blocking(globals.socket, false);

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, globals.socketname, sizeof(addr.sun_path)-1);

	ret = bind(globals.socket, (struct sockaddr *)&addr, sizeof(addr));
	assert(ret == 0);

	ret = chown(globals.socketname, geteuid(), getegid());
	assert(ret == 0);

	ret = chmod(globals.socketname, 0700);
	assert(ret == 0);

	ret = listen(globals.socket, 100);
	assert(ret == 0);

	return 0;
}

static int socket_server_wait_peer(void)
{
	struct sockaddr_un addr;
	socklen_t len;
	int fd;

	memset(&addr, 0, sizeof(addr));
	len = sizeof(addr);
	fd = accept(globals.socket, (struct sockaddr *)&addr, &len);
	assert(fd != -1);

	//set_blocking(fd, false);
	set_close_on_exec(fd);
	return fd;
}

static int socket_server_close(void)
{
	int ret;

	ret = close(globals.socket);
	assert(ret == 0);

	ret = unlink(globals.socketname);
	assert(ret == 0);

	return 0;
}

static int socket_client_connect(void)
{
	struct sockaddr_un addr;
	int client = 0;
	int ret;

	client = socket(AF_UNIX, SOCK_STREAM, 0);
	assert(client != -1);

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, globals.socketname, sizeof(addr.sun_path)-1);

	ret = connect(client, (struct sockaddr *)&addr, sizeof(addr));
	assert(ret == 0);

	return client;
}

static int socket_client_close(int client)
{
	int ret;

	ret = close(client);
	assert(ret == 0);

	return 0;
}

/*
  forked program
*/
static int fork_helper(void)
{
	pid_t pid;
	int client;

	pid = fork();
	assert(pid != -1);

	if (pid == 0) { // Child
		pid = getppid();
		client = socket_client_connect();
		while (kill(pid, 0) == 0) {
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

	test = ctdb_sys_check_iface_exists(fakename);
	if (geteuid() == 0) {
		assert(test == false);
	} else {
		assert(test == true);
	}
	return 0;
}

static int test_ctdb_get_peer_pid(void)
{
	int ret;
	int fd;
	pid_t peer_pid = 0;

	fd = socket_server_wait_peer();

	ret = ctdb_get_peer_pid(fd, &peer_pid);
	assert(ret == 0 || ret == ENOSYS);

	if (ret == 0) {
		assert(peer_pid == globals.helper_pid);

		kill(peer_pid, SIGTERM);
	} else {
		kill(globals.helper_pid, SIGTERM);
	}

	close(fd);
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
	int opt, ret;
	const char **extra_argv;
	int extra_argc = 0;
	poptContext pc;

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

	assert(globals.socketname != NULL);

	ret = socket_server_create();
	assert(ret == 0);

	/* FIXME: Test tcp_checksum6, tcp_checksum */
	/* FIXME: Test ctdb_sys_send_arp, ctdb_sys_send_tcp */
	/* FIXME: Test ctdb_sys_{open,close}_capture_socket, ctdb_sys_read_tcp_packet */
	test_ctdb_sys_check_iface_exists();

	ret = fork_helper();
	assert(ret == 0);
	test_ctdb_get_peer_pid();

	ret = socket_server_close();
	assert(ret == 0);

	return 0;
}
