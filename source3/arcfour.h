#ifndef _ARC4_H_
#define _ARC4_H_

/* 
   Unix SMB/Netbios implementation.
   Version 1.9.

   a implementation of arcfour designed for use in the 
   SMB password change protocol based on the description
   in 'Applied Cryptography', 2nd Edition.

   Copyright (C) Jeremy Allison 1997
   
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

typedef struct {
  unsigned char s_box[256];
  unsigned char index_i;
  unsigned char index_j;
} arc4_key;

#endif /* _ARC4_H_ */
