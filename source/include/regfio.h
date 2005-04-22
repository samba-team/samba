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

/************************************************************
 * Most of this information was obtained from 
 * http://www.wednesday.demon.co.uk/dosreg.html
 * Thanks Nigel!
 ***********************************************************/


#ifndef _REGFIO_H
#define _REGFIO_H

/* Macros */
 
#define REGF_BLOCKSIZE		0x1000

/* header sizes for various records */

#define REGF_HDR_SIZE		4
#define HBIN_HDR_SIZE		4
#define REC_HDR_SIZE		2

/* used by REGF_REC->type */

#define	REGF_TYPE_NK		1
#define	REGF_TYPE_LF		2
#define	REGF_TYPE_VK		3
#define	REGF_TYPE_SK		4

/* ??? List -- list of key offsets and hashed names for consistency */

typedef struct {
	uint32 nk_off;
	uint8 keycheck[sizeof(uint32)];
} REGF_HASH_REC;

typedef struct {
	char header[REC_HDR_SIZE];
	uint16 num_keys;
	REGF_HASH_REC *hashes;
} REGF_LF_REC;

/* Key Value */

typedef struct {
	uint32 hbin_off;
	
	char header[REC_HDR_SIZE];
	char *valuename;
	uint32 data_size;
	uint32 data_off;
	uint8  *data;
	uint32 type;
	uint16 flag;
} REGF_VK_REC;


/* Key Security */

typedef struct {
	char header[REC_HDR_SIZE];
	uint32 prev_sk_off;
	uint32 next_sk_off;
	uint32 ref_count;
	uint32 size;
	SEC_DESC *sec_desc;
} REGF_SK_REC;

/* Key Name */ 

typedef struct {
	uint32 hbin_off;	/* offset from beginning of this hbin block */
	
	/* header information */
	
	char header[REC_HDR_SIZE];
	uint16 key_type;
	NTTIME mtime;
	uint32 parent_off;	/* back pointer in registry hive */
	uint32 classname_off;	
	char *classname;
	char *keyname;
	
	/* children */
	
	uint32 num_subkeys;
	uint32 subkeys_off;	/* hash records that point to NK records */	
	uint32 num_values;
	uint32 values_off;	/* value lists which point to VK records */
	uint32 sk_off;		/* offset to SK record */
	
	/* link in the other records here */
	
	REGF_LF_REC subkeys;
	REGF_VK_REC *values;
	REGF_SK_REC *acl;
	
} REGF_NK_REC;


/* container for various record formats */

typedef struct {
	int type;		/* REGF_TYPE_XXX */
	union {
		REGF_NK_REC	nk;
		REGF_LF_REC	lf;
		REGF_VK_REC 	vk;
		REGF_SK_REC	sk;
	} data;
} REGF_REC;

/* HBIN block */

typedef struct {
	char   header[HBIN_HDR_SIZE];	/* "hbin" */
	uint32 first_hbin_off;		/* offset from first hbin block */
	uint32 next_hbin_off;		/* offset from next hbin block */
	uint32 block_size;		/* block size of this block (always 4kb) */
	uint32 data_size;		/* data size of this block -- not sure .... */

	prs_struct ps;			/* data */

	BOOL dirty;			/* should block be flushed to disk before releasing? */
} REGF_HBIN;

/* REGF block */
 
typedef struct {
	/* run time information */
	int fd;				/* file descriptor */
	TALLOC_CTX *mem_ctx;
	off_t current_block;		/* offset to the current file block */
	REGF_HBIN *current_hbin;	/* current hbin block */

	/* file format information */
	char   header[REGF_HDR_SIZE];	/* "regf" */
	uint32 data_offset;		/* offset to record in the first (or any?) hbin block */
	uint32 last_block;		/* offset to last hbin block in file */
	uint32 checksum;		/* XOR of bytes 0x0000 - 0x01FB */
	NTTIME mtime;
} REGF_FILE;


/* Function Declarations */
 
REGF_FILE* regfio_open( const char *filename, int flags, int mode );
REGF_REC*  regfio_next_record( REGF_FILE *file );
int        regfio_close( REGF_FILE *r );


#endif	/* _REGFIO_H */
