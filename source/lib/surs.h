/* 
   Unix SMB/Netbios implementation.
   Version 2.0
   Samba Utility Functions

   Copyright (C) Luke Kenneth Casson Leighton 2000
   
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

#ifndef _SURS_H_
#define _SURS_H_

typedef enum 
{
        SURS_POSIX_UID,	/* User id */
        SURS_POSIX_GID	/* Group id */

} 
posix_type;

typedef struct _surs_posix_id
{
        uint32 id;                 /* user/group id */
        posix_type type;           /* id type */
}
SURS_POSIX_ID;

typedef DOM_SID SURS_SID_ID;

#endif /* _SURS_H_ */
