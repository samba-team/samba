/*
   Unix SMB/CIFS implementation.

   file_id structure handling

   Copyright (C) Andrew Tridgell 2007

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
#include "lib/file_id.h"

/*
  return True if two file_id structures are equal
 */
bool file_id_equal(const struct file_id *id1, const struct file_id *id2)
{
	return id1->inode == id2->inode && id1->devid == id2->devid &&
	    id1->extid == id2->extid;
}

char *file_id_str_buf(struct file_id fid, struct file_id_buf *dst)
{
	snprintf(dst->buf,
		 sizeof(dst->buf),
		 "%"PRIu64":%"PRIu64":%"PRIu64,
		 fid.devid,
		 fid.inode,
		 fid.extid);
	return dst->buf;
}

/*
  push a 16 byte version of a file id into a buffer.  This ignores the extid
  and is needed when dev/inodes are stored in persistent storage (tdbs).
 */
void push_file_id_16(char *buf, const struct file_id *id)
{
	SIVAL(buf,  0, id->devid&0xFFFFFFFF);
	SIVAL(buf,  4, id->devid>>32);
	SIVAL(buf,  8, id->inode&0xFFFFFFFF);
	SIVAL(buf, 12, id->inode>>32);
}

/*
  push a 24 byte version of a file id into a buffer
 */
void push_file_id_24(char *buf, const struct file_id *id)
{
	SIVAL(buf,  0, id->devid&0xFFFFFFFF);
	SIVAL(buf,  4, id->devid>>32);
	SIVAL(buf,  8, id->inode&0xFFFFFFFF);
	SIVAL(buf, 12, id->inode>>32);
	SIVAL(buf, 16, id->extid&0xFFFFFFFF);
	SIVAL(buf, 20, id->extid>>32);
}

/*
  pull a 24 byte version of a file id from a buffer
 */
void pull_file_id_24(const char *buf, struct file_id *id)
{
	ZERO_STRUCTP(id);
	id->devid  = IVAL(buf,  0);
	id->devid |= ((uint64_t)IVAL(buf,4))<<32;
	id->inode  = IVAL(buf,  8);
	id->inode |= ((uint64_t)IVAL(buf,12))<<32;
	id->extid  = IVAL(buf,  16);
	id->extid |= ((uint64_t)IVAL(buf,20))<<32;
}

uint64_t make_file_id_from_itime(SMB_STRUCT_STAT *st)
{
	struct timespec itime = st->st_ex_itime;
	ino_t ino = st->st_ex_ino;
	uint64_t file_id_low;
	uint64_t file_id;

	if (st->st_ex_iflags & ST_EX_IFLAG_CALCULATED_ITIME) {
		return ino;
	}

	round_timespec_to_nttime(&itime);

	file_id_low = itime.tv_nsec;
	if (file_id_low == 0) {
		/*
		 * This could be by coincidence, but more likely the filesystem
		 * is only giving us seconds granularity. We need more fine
		 * grained granularity for the File-ID, so combine with the
		 * inode number.
		 */
		file_id_low = ino & ((1 << 30) - 1);
	}

	/*
	 * Set the high bit so ideally File-IDs based on inode numbers and
	 * File-IDs based on Birth Time use disjoint ranges, given inodes never
	 * have the high bit set.
	 */
	file_id = ((uint64_t)1) << 63;
	file_id |= (uint64_t)itime.tv_sec << 30;
	file_id |= file_id_low;

	return file_id;
}
