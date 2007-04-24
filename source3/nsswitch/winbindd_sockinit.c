/* 
   Unix SMB/CIFS implementation.
   Copyright (C) Tim Potter 2000-2001
   Copyright (C) 2001 by Martin Pool <mbp@samba.org>
   Copyright (C) James Peach 2007
   
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
#include "winbindd.h"
#include "smb_launchd.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_WINBIND

/* Open the winbindd socket */

static int _winbindd_socket = -1;
static int _winbindd_priv_socket = -1;
static BOOL unlink_winbindd_socket = True;

static int open_winbindd_socket(void)
{
	if (_winbindd_socket == -1) {
		_winbindd_socket = create_pipe_sock(
			WINBINDD_SOCKET_DIR, WINBINDD_SOCKET_NAME, 0755);
		DEBUG(10, ("open_winbindd_socket: opened socket fd %d\n",
			   _winbindd_socket));
	}

	return _winbindd_socket;
}

static int open_winbindd_priv_socket(void)
{
	if (_winbindd_priv_socket == -1) {
		_winbindd_priv_socket = create_pipe_sock(
			get_winbind_priv_pipe_dir(), WINBINDD_SOCKET_NAME, 0750);
		DEBUG(10, ("open_winbindd_priv_socket: opened socket fd %d\n",
			   _winbindd_priv_socket));
	}

	return _winbindd_priv_socket;
}

/* Close the winbindd socket */

static void close_winbindd_socket(void)
{
	if (_winbindd_socket != -1) {
		DEBUG(10, ("close_winbindd_socket: closing socket fd %d\n",
			   _winbindd_socket));
		close(_winbindd_socket);
		_winbindd_socket = -1;
	}
	if (_winbindd_priv_socket != -1) {
		DEBUG(10, ("close_winbindd_socket: closing socket fd %d\n",
			   _winbindd_priv_socket));
		close(_winbindd_priv_socket);
		_winbindd_priv_socket = -1;
	}
}

BOOL winbindd_init_sockets(int *public_sock, int *priv_sock,
				int *idle_timeout_sec)
{
	struct smb_launch_info linfo;

	if (smb_launchd_checkin_names(&linfo, "WinbindPublicPipe",
		    "WinbindPrivilegedPipe", NULL)) {
		if (linfo.num_sockets != 2) {
			DEBUG(0, ("invalid launchd configuration, "
				"expected 2 sockets but got %d\n",
				linfo.num_sockets));
			return False;
		}

		*public_sock = _winbindd_socket = linfo.socket_list[0];
		*priv_sock = _winbindd_priv_socket = linfo.socket_list[1];
		*idle_timeout_sec = linfo.idle_timeout_secs;

		unlink_winbindd_socket = False;

		smb_launchd_checkout(&linfo);
		return True;
	} else {
		*public_sock = open_winbindd_socket();
		*priv_sock = open_winbindd_priv_socket();
		*idle_timeout_sec = -1;

		if (*public_sock == -1 || *priv_sock == -1) {
			DEBUG(0, ("failed to open winbindd pipes: %s\n",
			    errno ? strerror(errno) : "unknown error"));
			return False;
		}

		return True;
	}
}

void winbindd_release_sockets(void)
{
	pstring path;

	close_winbindd_socket();

	/* Remove socket file */
	if (unlink_winbindd_socket) {
		pstr_sprintf(path, "%s/%s",
			 WINBINDD_SOCKET_DIR, WINBINDD_SOCKET_NAME);
		unlink(path);
	}
}

