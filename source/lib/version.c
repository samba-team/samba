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
#ifdef SAMBA_VERSION_VENDOR_FUNCTION
	return SAMBA_VERSION_VENDOR_FUNCTION;
#else /* SAMBA_VERSION_VENDOR_FUNCTION */
 #ifdef SAMBA_VERSION_VENDOR_SUFFIX
  #ifdef SAMBA_VERSION_VENDOR_PATCH
	return SAMBA_VERSION_OFFICIAL_STRING "-" SAMBA_VERSION_VENDOR_SUFFIX \
		"-" SAMBA_VERSION_VENDOR_PATCH_STRING;
  #endif /* SAMBA_VERSION_VENDOR_PATCH */
	return SAMBA_VERSION_OFFICIAL_STRING "-" SAMBA_VERSION_VENDOR_SUFFIX;
 #endif /* SAMBA_VERSION_VENDOR_SUFFIX */
#endif /* SAMBA_VERSION_VENDOR_FUNCTION */
	return SAMBA_VERSION_OFFICIAL_STRING;
}
