/*
   Unix SMB/Netbios implementation.

   Copyright (C) Ralph Boehme 2019
   Copyright (C) Stefan Metzmacher 2019

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "includes.h"
#include "system/filesys.h"
#include "system/threads.h"
#ifdef HAVE_UNSHARE_CLONE_FS
#include <sched.h>
#endif /* HAVE_UNSHARE_CLONE_FS */

static bool _per_thread_cwd_checked;
static bool _per_thread_cwd_supported;
#ifdef HAVE_UNSHARE_CLONE_FS
static __thread bool _per_thread_cwd_disabled;
static __thread bool _per_thread_cwd_activated;
#endif /* HAVE_UNSHARE_CLONE_FS */

/*
 * This is the first function to be called!
 * Typically in the main() function before
 * any threads are created.
 *
 * This can be called multiple times
 * as the result is cached the first time.
 */
void per_thread_cwd_check(void)
{
	if (_per_thread_cwd_checked) {
		return;
	}

#ifdef HAVE_UNSHARE_CLONE_FS
	/*
	 * While unshare(CLONE_FS) is available on
	 * Linux for ages, unshare() is also
	 * used to implement containers with various
	 * per container namespaces.
	 *
	 * It's possible that the whole unshare()
	 * is blocked in order to disallow neested
	 * containers.
	 *
	 * That's why we sadly need a runtime check
	 * for this.
	 */
	{
		int res;

		res = unshare(CLONE_FS);
		if (res == 0) {
			_per_thread_cwd_supported = true;
		}
	}

	/*
	 * We're in the main thread, so we should disallow
	 * per_thread_cwd_activate() here.
	 */
	_per_thread_cwd_disabled = true;
#endif /* HAVE_UNSHARE_CLONE_FS */

	_per_thread_cwd_checked = true;
}

/*
 * In order to use per_thread_cwd_supported()
 * per_thread_cwd_check() needs to be called first!
 * Otherwise an assert will be triggered!
 */
bool per_thread_cwd_supported(void)
{
	SMB_ASSERT(_per_thread_cwd_checked);
	return _per_thread_cwd_supported;
}

/*
 * In order to use per_thread_cwd_disable()
 * should be called after any fork() in order
 * to mark the main thread of the process,
 * which should disallow per_thread_cwd_activate().
 *
 * This can be called without calling
 * per_thread_cwd_check() first.
 *
 * And it can't be called after calling
 * per_thread_cwd_activate()!
 * Otherwise an assert will be triggered!
 *
 * This can be called multiple times
 * as the result is cached the first time.
 */
void per_thread_cwd_disable(void)
{
#ifdef HAVE_UNSHARE_CLONE_FS
	SMB_ASSERT(!_per_thread_cwd_activated);
	if (_per_thread_cwd_disabled) {
		return;
	}
	_per_thread_cwd_disabled = true;
#endif /* HAVE_UNSHARE_CLONE_FS */
}

/*
 * In order to use per_thread_cwd_activate()
 * per_thread_cwd_supported() needs to be checked first!
 * Otherwise an assert will be triggered!
 *
 * This MUST only be called within helper threads!
 *
 * That means it can't be called after calling
 * per_thread_cwd_disable()!
 * Otherwise an assert will be triggered!
 *
 * This can be called multiple times
 * as the result is cached the first time.
 */
void per_thread_cwd_activate(void)
{
	SMB_ASSERT(_per_thread_cwd_checked);
	SMB_ASSERT(_per_thread_cwd_supported);

#ifdef HAVE_UNSHARE_CLONE_FS
	if (_per_thread_cwd_activated) {
		return;
	}

	SMB_ASSERT(!_per_thread_cwd_disabled);

	{
		int ret;
		ret = unshare(CLONE_FS);
		SMB_ASSERT(ret == 0);
	}

	_per_thread_cwd_activated = true;
#else /* not HAVE_UNSHARE_CLONE_FS */
	smb_panic(__location__);
#endif /* not HAVE_UNSHARE_CLONE_FS */
}
