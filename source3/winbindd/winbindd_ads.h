/*
   Unix SMB/CIFS implementation.

   Winbind ADS backend functions

   Copyright (C) Volker Lendecke 2017

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

#ifndef __WINBINDD_ADS_H__
#define __WINBINDD_ADS_H__


#include "ads.h"

extern struct winbindd_methods ads_methods;

ADS_STATUS ads_idmap_cached_connection(ADS_STRUCT **adsp,
				       const char *dom_name);

#endif
