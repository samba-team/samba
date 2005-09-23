/* 
   Unix SMB/CIFS implementation.
   Samba system utilities
   Copyright (C) Andrew Tridgell 1992-1998
   Copyright (C) Jeremy Allison 1998-2002
   
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

#ifndef HAVE_DLOPEN
void *dlopen(const char *name, int flags)
{
	return NULL;
}
#endif

#ifndef HAVE_DLSYM
void *dlsym(void *handle, const char *symbol)
{
    return NULL;
}
#endif

#ifndef HAVE_DLERROR
const char *dlerror(void)
{
	return "dynamic loading of objects not supported on this platform";
}
#endif

#ifndef HAVE_DLCLOSE
int dlclose(void *handle)
{
	return 0;
}
#endif
