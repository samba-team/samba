/*
   Unix SMB/CIFS implementation.
   Launchd integration wrapper API

   Copyright (C) 2007 James Peach

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

/* launchd source code and documentation is available here:
 *	http://launchd.macosforge.org/
 */

#if defined(WITH_LAUNCHD_SUPPORT)

#include <launch.h>
#include <stdarg.h>

typedef void (*launchd_iterator)(launch_data_t, const char*, void*);

#define LAUNCHD_TRACE_LEVEL 10

 void smb_launchd_checkout(struct smb_launch_info *linfo)
{
	talloc_free(linfo->socket_list);
}

static void pull_launch_sockets(launch_data_t key,
				const char *name,
				struct smb_launch_info *linfo)
{
	launch_data_type_t type;

	type = launch_data_get_type(key);
	DEBUG(LAUNCHD_TRACE_LEVEL,
		("Searching item name='%s' type=%d for sockets\n",
		 name ? name : "", (int)type));

	switch (type) {
	case LAUNCH_DATA_FD:
		if (!linfo->socket_list) {
			/* We are counting the number of sockets. */
			linfo->num_sockets++;
		} else {
			/* We are collecting the socket fds. */
			int fd = launch_data_get_fd(key);

			linfo->socket_list[linfo->num_sockets] = fd;
			linfo->num_sockets++;
			DEBUG(LAUNCHD_TRACE_LEVEL,
				("Added fd=%d to launchd set\n", fd));
		}
		return;
	case LAUNCH_DATA_ARRAY:
	{
		int i;
		launch_data_t item;

		for (i = 0; i < launch_data_array_get_count(key); ++i) {
			item = launch_data_array_get_index(key, i);
			pull_launch_sockets(item, name, linfo);
		}
		return;
	}
	case LAUNCH_DATA_DICTIONARY:
		launch_data_dict_iterate(key,
			(launchd_iterator)pull_launch_sockets, linfo);
		return;
	default:
		return;
	}
}

 BOOL smb_launchd_checkin_names(struct smb_launch_info *linfo, ...)
{
	launch_data_t msg;
	launch_data_t resp;
	launch_data_t item;
	BOOL is_launchd = False;

	ZERO_STRUCTP(linfo);

	msg = launch_data_new_string(LAUNCH_KEY_CHECKIN);
	resp = launch_msg(msg);
	if (resp == NULL) {
		/* IPC to launchd failed. */
		launch_data_free(msg);
		return is_launchd;
	}

	if (launch_data_get_type(resp) == LAUNCH_DATA_ERRNO) {
		errno = launch_data_get_errno(resp);
		goto done;
	}

	/* At this point, we know we are running under launchd. */
	linfo->idle_timeout_secs = 600;
	is_launchd = True;

	if ((item = launch_data_dict_lookup(resp, LAUNCH_JOBKEY_TIMEOUT))) {
		linfo->idle_timeout_secs = launch_data_get_integer(item);
	}

	if ((item = launch_data_dict_lookup(resp, LAUNCH_JOBKEY_SOCKETS))) {
		int count = 0;
		const char * sockname = NULL;
		launch_data_t sockdata;
		va_list args;

		/* Figure out the maximum number of sockets. */
		va_start(args, linfo);
		while ((sockname = va_arg(args, const char *))) {
		    ++count;
		}
		va_end(args);

		DEBUG(LAUNCHD_TRACE_LEVEL, ("Found %d launchd sockets\n",
					linfo->num_sockets));

		if (launch_data_dict_get_count(item) < count) {
			DEBUG(0, ("%d launchd sockets requested, "
			    "but only %d are available\n",
			    count, launch_data_dict_get_count(item)));
		}

		linfo->socket_list = talloc_array(NULL, int, count);
		if (linfo->socket_list == NULL) {
			goto done;
		}

		linfo->num_sockets = 0;
		va_start(args, linfo);
		while ((sockname = va_arg(args, const char *))) {
		    sockdata = launch_data_dict_lookup(item, sockname);

		    pull_launch_sockets(sockdata, sockname, linfo);
		    DEBUG(LAUNCHD_TRACE_LEVEL,
			    ("Added launchd socket \"%s\"\n", sockname));
		}

		SMB_ASSERT(count >= linfo->num_sockets);
	}

done:
	launch_data_free(msg);
	launch_data_free(resp);
	return is_launchd;
}

 BOOL smb_launchd_checkin(struct smb_launch_info *linfo)
{
	launch_data_t msg;
	launch_data_t resp;
	launch_data_t item;
	BOOL is_launchd = False;

	ZERO_STRUCTP(linfo);

	msg = launch_data_new_string(LAUNCH_KEY_CHECKIN);
	resp = launch_msg(msg);
	if (resp == NULL) {
		/* IPC to launchd failed. */
		launch_data_free(msg);
		return is_launchd;
	}

	if (launch_data_get_type(resp) == LAUNCH_DATA_ERRNO) {
		errno = launch_data_get_errno(resp);
		goto done;
	}

	/* At this point, we know we are running under launchd. */
	linfo->idle_timeout_secs = 600;
	is_launchd = True;

	if ((item = launch_data_dict_lookup(resp, LAUNCH_JOBKEY_TIMEOUT))) {
		linfo->idle_timeout_secs = launch_data_get_integer(item);
	}

	if ((item = launch_data_dict_lookup(resp, LAUNCH_JOBKEY_SOCKETS))) {
		int count;

		pull_launch_sockets(item, NULL, linfo);
		DEBUG(LAUNCHD_TRACE_LEVEL, ("Found %d launchd sockets\n",
					linfo->num_sockets));

		count = linfo->num_sockets;
		linfo->socket_list = talloc_array(NULL, int, count);
		if (linfo->socket_list == NULL) {
			goto done;
		}

		linfo->num_sockets = 0;
		pull_launch_sockets(item, NULL, linfo);

		DEBUG(LAUNCHD_TRACE_LEVEL, ("Added %d launchd sockets\n",
					linfo->num_sockets));

		SMB_ASSERT(count == linfo->num_sockets);
	}

done:
	launch_data_free(msg);
	launch_data_free(resp);
	return is_launchd;
}

#else /* defined(WITH_LAUNCHD_SUPPORT) */

 BOOL smb_launchd_checkin(struct smb_launch_info * UNUSED(linfo))
{
	ZERO_STRUCTP(linfo);
	return False;
}

 BOOL smb_launchd_checkin_names(struct smb_launch_info * UNUSED(linfo), ...)
{
	ZERO_STRUCTP(linfo);
	return False;
}

 void smb_launchd_checkout(struct smb_launch_info * UNUSED(linfo))
{
}

#endif /* defined(WITH_LAUNCHD_SUPPORT) */

