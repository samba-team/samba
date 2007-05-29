/* 
   Unix SMB/CIFS implementation.

   file_id structure handling

   Copyright (C) Andrew Tridgell 2007
   
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

/*
  return a file_id which gives a unique ID for a file given the device and
  inode numbers
 */
struct file_id file_id_create(SMB_DEV_T dev, SMB_INO_T inode)
{
	struct file_id key;
	/* the ZERO_STRUCT ensures padding doesn't break using the key as a
	 * blob */
	ZERO_STRUCT(key);
	key.devid = dev;
	key.inode = inode;
	return key;
}

/*
  generate a file_id from a stat structure
 */
struct file_id file_id_sbuf(const SMB_STRUCT_STAT *sbuf)
{
	return file_id_create(sbuf->st_dev, sbuf->st_ino);
}


/*
  return True if two file_id structures are equal
 */
BOOL file_id_equal(const struct file_id *id1, const struct file_id *id2)
{
	return id1->inode == id2->inode && id1->devid == id2->devid;
}

/*
  a static string for a file_id structure
 */
const char *file_id_static_string(const struct file_id *id)
{
	static char buf[32];
	snprintf(buf, sizeof(buf), "%llx:%llx", 
		 (unsigned long long)id->devid, 
		 (unsigned long long)id->inode);
	return buf;
}

/*
  a 2nd static string for a file_id structure so we can print 2 at once
 */
const char *file_id_static_string2(const struct file_id *id)
{
	static char buf[32];
	snprintf(buf, sizeof(buf), "%llx:%llx", 
		 (unsigned long long)id->devid, 
		 (unsigned long long)id->inode);
	return buf;
}

/*
  push a 16 byte version of a file id into a buffer
 */
void push_file_id_16(char *buf, const struct file_id *id)
{
	SIVAL(buf,  0, id->devid&0xFFFFFFFF);
	SIVAL(buf,  4, id->devid>>32);
	SIVAL(buf,  8, id->inode&0xFFFFFFFF);
	SIVAL(buf, 12, id->inode>>32);
}

/*
  pul a 16 byte version of a file id from a buffer
 */
void pull_file_id_16(char *buf, struct file_id *id)
{
	ZERO_STRUCTP(id);
	id->devid  = IVAL(buf,  0);
	id->devid |= ((uint64_t)IVAL(buf,4))<<32;
	id->inode  = IVAL(buf,  8);
	id->inode |= ((uint64_t)IVAL(buf,12))<<32;
}
