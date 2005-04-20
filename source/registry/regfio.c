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

#include "includes.h"
#include "regfio.h"


/*******************************************************************
*******************************************************************/

static int write_block( prs_struct *ps, off_t file_offset, int fd )
{
	int bytes_written, returned;
	char *buffer = prs_data_p( ps );
	
	if ( fd == -1 || !buffer )
		return -1;
		
	if ( lseek( fd, file_offset, SEEK_SET ) == -1 ) {
		DEBUG(0,("write_block: lseek() failed! (%s)\n", strerror(errno) ));
		return -1;
	}
	
	bytes_written = returned = 0;
	while ( bytes_written < REGF_BLOCKSIZE ) {
		if ( (returned = write( fd, buffer+bytes_written, REGF_BLOCKSIZE-bytes_written )) == -1 ) {
			DEBUG(0,("write_block: write() failed! (%s)\n", strerror(errno) ));
			return False;
		}
				
		bytes_written += returned;
	}
	
	return bytes_written;
}

/*******************************************************************
*******************************************************************/

static int read_block( prs_struct *ps, off_t file_offset, int fd )
{
	int bytes_read, returned;
	char *buffer;
	
	if ( prs_data_size(ps) < REGF_BLOCKSIZE )
		prs_alloc_mem( ps, REGF_BLOCKSIZE, 1 );
		
	buffer = prs_data_p( ps );
	
	if ( lseek( fd, file_offset, SEEK_SET ) == -1 ) {
		DEBUG(0,("write_block: lseek() failed! (%s)\n", strerror(errno) ));
		return -1;
	}
	
	/* read in regf block here */
	
	bytes_read = returned = 0;
	while ( bytes_read < REGF_BLOCKSIZE ) {
		if ( (returned = read( fd, buffer+bytes_read, REGF_BLOCKSIZE-bytes_read )) == -1 ) {
			DEBUG(0,("read_block: read() failed (%s)\n", strerror(errno) ));
			return False;
		}
		if ( (returned == 0) && (bytes_read < REGF_BLOCKSIZE) ) {
			DEBUG(0,("read_block: not a vald registry file ?\n" ));
			return False;
		}	
		
		bytes_read += returned;
	}
	
	prs_set_offset(ps, 0 );
	
	return bytes_read;
}

/*******************************************************************
*******************************************************************/

static BOOL prs_regf_block( const char *desc, prs_struct *ps, int depth, REGF_FILE *file )
{
	prs_debug(ps, depth, desc, "prs_regf_block");
	depth++;
	
	if ( !prs_uint8s( True, "header", ps, depth, file->header, sizeof( file->header )) )
		return False;
	
	/* get the modtime */
	
	if ( !prs_set_offset( ps, 0x0c ) )
		return False;
	if ( !smb_io_time( "modtime", &file->mtime, ps, depth ) )
		return False;

	/* get file offsets */
	
	if ( !prs_set_offset( ps, 0x24 ) )
		return False;
	if ( !prs_uint32( "data_offset", ps, depth, &file->data_offset ))
		return False;
	if ( !prs_uint32( "last_block", ps, depth, &file->last_block ))
		return False;
		
	/* get the checksum */
	
	if ( !prs_set_offset( ps, 0x01fc ) )
		return False;
	if ( !prs_uint32( "checksum", ps, depth, &file->checksum ))
		return False;
	
	return True;
}

/*******************************************************************
*******************************************************************/

static uint32 regf_block_checksum( prs_struct *ps )
{
	char *buffer = prs_data_p( ps );
	uint32 checksum, x;
	int i;

	/* XOR of all bytes 0x0000 - 0x01FB */
		
	checksum = x = 0;
	
	for ( i=0; i<0x01FB; i+=4 ) {
		x = IVAL(buffer, i );
		checksum ^= x;
	}
	
	return checksum;
}

/*******************************************************************
*******************************************************************/

static BOOL read_regf_block( REGF_FILE *file )
{
	prs_struct ps;
	TALLOC_CTX *ctx;
	uint32 checksum;
	
	if ( !(ctx = talloc_init( "read_regf_block" )) ) {
		DEBUG(0,("read_regf_block: talloc_init() failed!\n"));
		return False;
	}

	prs_init( &ps, 0, ctx, UNMARSHALL );
	
	/* grab the first block from the file */
		
	if ( read_block( &ps, 0, file->fd ) == -1 )
		return False;
	
	/* parse the block and verify the checksum */
	
	if ( !prs_regf_block( "regf_header", &ps, 0, file ) )
		return False;	
		
	checksum = regf_block_checksum( &ps );
	
	prs_mem_free( &ps );
	
	if ( file->checksum !=  checksum ) {
		DEBUG(0,("regfio_open: invalid checksum\n" ));
		return False;
	}

	return True;
}

/*******************************************************************
 Open the registry file and then read in the REGF block to get the 
 first hbin offset.
*******************************************************************/

REGF_FILE* regfio_open( const char *filename, int flags, int mode )
{
	REGF_FILE *rb;

	
	
	if ( !(rb = (REGF_FILE*)malloc( sizeof(REGF_FILE) )) ) {
		DEBUG(0,("ERROR allocating memory\n"));
		return NULL;
	}
	
	/* open and existing file */

	if ( (rb->fd = open(filename, flags, mode)) == -1 ) {
		DEBUG(0,("regfio_open: failure to open %s (%s)\n", filename, strerror(errno)));
		regfio_close( rb );
		return NULL;
	}
	
	/* check if we are creating a new file or overwriting an existing one */
	
	if ( flags & (O_CREAT|O_TRUNC) ) {
		/* init_regf_block( rb ); */
		return rb;
	}
	
	/* read in an existing file */
	
	if ( !read_regf_block( rb ) ) {
		DEBUG(0,("regfio_open: Failed to read initial REGF block\n"));
		regfio_close( rb );
		return NULL;
	}

	return rb;

}

/*******************************************************************
*******************************************************************/

int regfio_close( REGF_FILE *r )
{
	int fd;

	/* nothing tdo do if there is no open file */

	if ( !r || (r->fd == -1) )
		return 0;
		
	fd = r->fd;
	r->fd = -1;
	SAFE_FREE( r );

	return close( fd );
}


