/* 
   Unix SMB/CIFS implementation.
   Samba Version functions
   
   Copyright (C) Stefan Metzmacher	2003
   
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
#include "version.h"

const char *samba_version_string(void)
{
	const char *official_string = SAMBA_VERSION_OFFICIAL_STRING;
#ifdef SAMBA_VERSION_RELEASE_NICKNAME
 	const char *release_nickname = SAMBA_VERSION_RELEASE_NICKNAME;
#else
 	const char *release_nickname = NULL;
#endif
#ifdef SAMBA_VERSION_VENDOR_SUFFIX
 	const char *vendor_suffix = SAMBA_VERSION_VENDOR_SUFFIX;
#else
 	const char *vendor_suffix = NULL;
#endif
#ifdef SAMBA_VERSION_VENDOR_PATCH
 	const char *vendor_patch = SAMBA_VERSION_VENDOR_PATCH;
#else
 	const char *vendor_patch = NULL;
#endif
	static char *samba_version;
	static BOOL init_samba_version;

	if (init_samba_version) {
		return samba_version;
	}

	samba_version = talloc_asprintf(talloc_autofree_context(),
					"%s%s%s%s%s%s%s%s",
					official_string,
					(vendor_suffix?"-":""),
					(vendor_suffix?vendor_suffix:""),
					(vendor_patch?"-":""),
					(vendor_patch?vendor_patch:""),
					(release_nickname?" (":""),
					(release_nickname?release_nickname:""),
					(release_nickname?")":""));

	init_samba_version = True;
	return samba_version;
}
