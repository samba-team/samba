/* 
   Unix SMB/CIFS implementation.
   Samba Version functions
   
   Copyright (C) Stefan Metzmacher	2003
   
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
#include <assert.h>

const char *samba_version_string(void)
{
#ifndef SAMBA_VERSION_VENDOR_SUFFIX
	return SAMBA_VERSION_OFFICIAL_STRING;
#else
	static char *samba_version;
	int res;
#ifdef SAMBA_VERSION_VENDOR_PATCH
	char *tmp_version;
#endif

	if (samba_version != NULL)
		return samba_version;

	res = asprintf(&samba_version, "%s-%s",
		       SAMBA_VERSION_OFFICIAL_STRING,
		       SAMBA_VERSION_VENDOR_SUFFIX);
	/*
	 * Can't use smb_panic here due to dependencies
	 */
	assert(res != -1);

#ifdef SAMBA_VERSION_VENDOR_PATCH
	res = asprintf(&tmp_version, "%s-%d", samba_version,
		       SAMBA_VERSION_VENDOR_PATCH);
	/*
	 * Can't use smb_panic here due to dependencies
	 */
	assert(res != -1);

	SAFE_FREE(samba_version);

	samba_version = tmp_version;
#endif

	return samba_version;
#endif
}

void samba_extended_info_version(struct smb_extended_info *extended_info)
{
	assert(extended_info != NULL);

	extended_info->samba_magic = SAMBA_EXTENDED_INFO_MAGIC;
	extended_info->samba_version = ((SAMBA_VERSION_MAJOR & 0xff) << 24)
				       | ((SAMBA_VERSION_MINOR & 0xff) << 16)
				       | ((SAMBA_VERSION_RELEASE & 0xff) << 8);
#ifdef SAMBA_VERSION_REVISION
	extended_info->samba_version |= (tolower(*SAMBA_VERSION_REVISION) - 'a' + 1) & 0xff;
#endif
#ifdef SAMBA_VERSION_RC_RELEASE
	extended_info->samba_subversion |= (SAMBA_VERSION_RC_RELEASE & 0xff) << 24;
#else
#ifdef SAMBA_VERSION_PRE_RELEASE
	extended_info->samba_subversion |= (SAMBA_VERSION_PRE_RELEASE & 0xff) << 16;
#endif
#endif
#ifdef SAMBA_VERSION_VENDOR_PATCH
	extended_info->samba_subversion |= (SAMBA_VERSION_VENDOR_PATCH & 0xffff);
#endif
	/* FIXME: samba_gitcommitdate should contain the git commit date. */
	unix_to_nt_time(&extended_info->samba_gitcommitdate, time(NULL));

	snprintf (extended_info->samba_version_string,
		  SAMBA_EXTENDED_INFO_VERSION_STRING_LENGTH,
		  "%s", samba_version_string());
}
