/* 
   Unix SMB/Netbios implementation.
   Version 2.0

   a common place to work out how to define NSS_STATUS on various
   platforms

   Copyright (C) Tim Potter 2000
   
   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public
   License as published by the Free Software Foundation; either
   version 2 of the License, or (at your option) any later version.
   
   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.
   
   You should have received a copy of the GNU Library General Public
   License along with this library; if not, write to the
   Free Software Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA  02111-1307, USA.   
*/

#ifdef HAVE_NSS_COMMON_H

/* Sun Solaris */

#include <nss_common.h>
#include <nss_dbdefs.h>
#include <nsswitch.h>

typedef nss_status_t NSS_STATUS;

#define NSS_STATUS_SUCCESS     NSS_SUCCESS
#define NSS_STATUS_NOTFOUND    NSS_NOTFOUND
#define NSS_STATUS_UNAVAIL     NSS_UNAVAIL
#define NSS_STATUS_TRYAGAIN    NSS_TRYAGAIN

#elif HAVE_NSS_H

/* GNU */

#include <nss.h>

typedef enum nss_status NSS_STATUS;

#else /* Nothing's defined. Neither gnu nor sun */

typedef enum
{
  NSS_STATUS_SUCCESS=0,
  NSS_STATUS_NOTFOUND=1,
  NSS_STATUS_UNAVAIL=2,
  NSS_STATUS_TRYAGAIN=3
} NSS_STATUS;

#endif

