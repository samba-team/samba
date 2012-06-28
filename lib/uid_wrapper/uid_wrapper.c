/*
   Copyright (C) Andrew Tridgell 2009
   Copyright (c) 2011      Andreas Schneider <asn@samba.org>
 
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

#ifdef _SAMBA_BUILD_

#define UID_WRAPPER_NOT_REPLACE
#include "replace.h"
#include "system/passwd.h"
#include <talloc.h>
#include "../lib/util/setid.h"

#else /* _SAMBA_BUILD_ */

#error uid_wrapper_only_supported_in_samba_yet

#endif

#ifndef _PUBLIC_
#define _PUBLIC_
#endif

/*
  we keep the virtualised euid/egid/groups information here
 */
static struct {
	bool initialised;
	bool enabled;
	uid_t myuid;
	uid_t euid;
	uid_t mygid;
	gid_t egid;
	gid_t *groups;
} uwrap;

static void uwrap_init(void)
{
	if (uwrap.initialised) return;
	uwrap.initialised = true;
	if (getenv("UID_WRAPPER")) {
		uwrap.enabled = true;
		/* put us in one group */
		uwrap.myuid = uwrap.euid = geteuid();
		uwrap.mygid = uwrap.egid = getegid();
		uwrap.groups = talloc_array(NULL, gid_t, 1);
		uwrap.groups[0] = 0;
	}
}

#undef uwrap_enabled
_PUBLIC_ int uwrap_enabled(void)
{
	uwrap_init();
	return uwrap.enabled?1:0;
}

#ifdef HAVE_SETEUID
_PUBLIC_ int uwrap_seteuid(uid_t euid)
{
	uwrap_init();
	if (!uwrap.enabled) {
		return samba_seteuid(euid);
	}
	/* assume for now that the ruid stays as root */
	if (euid == 0) {
		uwrap.euid = uwrap.myuid;
	} else {
		uwrap.euid = euid;
	}
	return 0;
}
#endif

#ifdef HAVE_SETREUID
_PUBLIC_ int uwrap_setreuid(uid_t ruid, uid_t euid)
{
	uwrap_init();
	if (!uwrap.enabled) {
		return samba_setreuid(ruid, euid);
	}
	/* assume for now that the ruid stays as root */
	if (euid == 0) {
		uwrap.euid = uwrap.myuid;
	} else {
		uwrap.euid = euid;
	}
	return 0;
}
#endif

#ifdef HAVE_SETRESUID
_PUBLIC_ int uwrap_setresuid(uid_t ruid, uid_t euid, uid_t suid)
{
	uwrap_init();
	if (!uwrap.enabled) {
		return samba_setresuid(ruid, euid, suid);
	}
	/* assume for now that the ruid stays as root */
	if (euid == 0) {
		uwrap.euid = uwrap.myuid;
	} else {
		uwrap.euid = euid;
	}
	return 0;
}
#endif

_PUBLIC_ uid_t uwrap_geteuid(void)
{
	uwrap_init();
	if (!uwrap.enabled) {
		return geteuid();
	}
	return uwrap.euid;
}

#ifdef HAVE_SETEGID
_PUBLIC_ int uwrap_setegid(gid_t egid)
{
	uwrap_init();
	if (!uwrap.enabled) {
		return samba_setegid(egid);
	}
	/* assume for now that the ruid stays as root */
	if (egid == 0) {
		uwrap.egid = uwrap.mygid;
	} else {
		uwrap.egid = egid;
	}
	return 0;
}
#endif

#ifdef HAVE_SETREGID
_PUBLIC_ int uwrap_setregid(gid_t rgid, gid_t egid)
{
	uwrap_init();
	if (!uwrap.enabled) {
		return samba_setregid(rgid, egid);
	}
	/* assume for now that the ruid stays as root */
	if (egid == 0) {
		uwrap.egid = uwrap.mygid;
	} else {
		uwrap.egid = egid;
	}
	return 0;
}
#endif

#ifdef HAVE_SETRESGID
_PUBLIC_ int uwrap_setresgid(gid_t rgid, gid_t egid, gid_t sgid)
{
	uwrap_init();
	if (!uwrap.enabled) {
		return samba_setresgid(rgid, egid, sgid);
	}
	/* assume for now that the ruid stays as root */
	if (egid == 0) {
		uwrap.egid = uwrap.mygid;
	} else {
		uwrap.egid = egid;
	}
	return 0;
}
#endif

_PUBLIC_ uid_t uwrap_getegid(void)
{
	uwrap_init();
	if (!uwrap.enabled) {
		return getegid();
	}
	return uwrap.egid;
}

_PUBLIC_ int uwrap_setgroups(size_t size, const gid_t *list)
{
	uwrap_init();
	if (!uwrap.enabled) {
		return samba_setgroups(size, list);
	}

	talloc_free(uwrap.groups);
	uwrap.groups = NULL;

	if (size != 0) {
		uwrap.groups = talloc_array(NULL, gid_t, size);
		if (uwrap.groups == NULL) {
			errno = ENOMEM;
			return -1;
		}
		memcpy(uwrap.groups, list, size*sizeof(gid_t));
	}
	return 0;
}

_PUBLIC_ int uwrap_getgroups(int size, gid_t *list)
{
	size_t ngroups;

	uwrap_init();
	if (!uwrap.enabled) {
		return getgroups(size, list);
	}

	ngroups = talloc_array_length(uwrap.groups);

	if (size > ngroups) {
		size = ngroups;
	}
	if (size == 0) {
		return ngroups;
	}
	if (size < ngroups) {
		errno = EINVAL;
		return -1;
	}
	memcpy(list, uwrap.groups, size*sizeof(gid_t));
	return ngroups;
}

_PUBLIC_ uid_t uwrap_getuid(void)
{
	uwrap_init();
	if (!uwrap.enabled) {
		return getuid();
	}
	/* we don't simulate ruid changing */
	return 0;
}

_PUBLIC_ gid_t uwrap_getgid(void)
{
	uwrap_init();
	if (!uwrap.enabled) {
		return getgid();
	}
	/* we don't simulate rgid changing */
	return 0;
}
