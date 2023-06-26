/* 
   Unix SMB/CIFS implementation.
   NT ioctl code constants
   Copyright (C) Andrew Tridgell              2002

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

#ifndef _NTIOCTL_H
#define _NTIOCTL_H

/* For FSCTL_GET_SHADOW_COPY_DATA ...*/
typedef char SHADOW_COPY_LABEL[25]; /* sizeof("@GMT-2004.02.18-15.44.00") + 1 */

struct shadow_copy_data {
	/* Total number of shadow volumes currently mounted */
	uint32_t num_volumes;
	/* Concatenated list of labels */
	SHADOW_COPY_LABEL *labels;
};


#endif /* _NTIOCTL_H */
