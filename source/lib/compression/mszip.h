/* mszip decompression - based on cabextract.c code from
 * Stuart Caie
 *
 * adapted for Samba by Andrew Tridgell and Stefan Metzmacher 2005
 *
 * (C) 2000-2001 Stuart Caie <kyzer@4u.net>
 * reaktivate-specifics by Malte Starostik <malte@kde.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

struct decomp_state;
struct decomp_state *ZIPdecomp_state(TALLOC_CTX *mem_ctx);

#define DECR_OK           (0)
#define DECR_DATAFORMAT   (1)
#define DECR_ILLEGALDATA  (2)
#define DECR_NOMEMORY     (3)
#define DECR_CHECKSUM     (4)
#define DECR_INPUT        (5)
#define DECR_OUTPUT       (6)
int ZIPdecompress(struct decomp_state *decomp_state, DATA_BLOB *inbuf, DATA_BLOB *outbuf);
