/*
 *  Unix SMB/CIFS implementation.
 *
 *  Process utils.
 *
 *  Copyright (c) 2013      Andreas Schneider <asn@samba.org>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "util_process.h"

#ifdef HAVE_SYS_PRCTL_H
#include <sys/prctl.h>
#endif

int prctl_set_comment(const char *comment)
{
#if defined(HAVE_PRCTL) && defined(PR_SET_NAME)
	return prctl(PR_SET_NAME, (unsigned long) comment, 0, 0, 0);
#endif
	return 0;
}
