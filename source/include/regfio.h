/*
   Windows NT registry I/O library 
   Copyright (c) Gerald (Jerry) Carter               2005

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

#ifndef _REGFIO_H
#define _REGFIO_H

/*
 * Macros
 */
 
#define REGF_HDR_SIZE		4
#define REGF_BLOCKSIZE		0x1000

/* 
 * REGF file information (including header block data)
 */
 
typedef struct {

} REGF_NK_RECORD;
 

typedef struct {

} REGF_LF_RECORD;

typedef struct {

} REGF_VK_RECORD;

typedef struct {

} REGF_SK_RECORD;

typedef struct {

} REGF_HASH_RECORD;

typedef struct {

} REGF_VALUE_LIST;

typedef struct {
	uint32 offset;			/* offset from fist hbin block */
	uint32 block_size;		/* block size of this block (always 4kb) */
	uint8 buffer[REGF_BLOCKSIZE];	/* data */
	BOOL dirty;			/* should block be flushed to disk before releasing? */
} REGF_HBIN;
 
typedef struct {
	/* run time information */
	int fd;				/* file descriptor */
	off_t current_block;		/* offset to the current file block */
	REGF_HBIN *current_hbin;	/* current hbin block */

	/* file format information */
	char   header[REGF_HDR_SIZE];	/* "regf" */
	uint32 data_offset;		/* offset to record in the first (or any?) hbin block */
	uint32 last_block;		/* offset to last hbin block in file */
	uint32 checksum;		/* XOR of bytes 0x0000 - 0x01FB */
	NTTIME mtime;
} REGF_FILE;


/* 
 * Function Declarations
 */
 
REGF_FILE* regfio_open( const char *filename, int flags, int mode );
int        regfio_close( REGF_FILE *r );


#endif	/* _REGFIO_H */
