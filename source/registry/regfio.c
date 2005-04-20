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
 Open the registry file and then read in the REGF block to get the 
 first hbin offset.
*******************************************************************/

REGF_FILE* regfio_open( const char *filename, int flags, int mode )
{
	REGF_FILE *rb;
	uint8 buffer[REGF_BLOCKSIZE];
	size_t num_bytes, returned;
	uint32 xor_value, x;
	int i;
	char header[REGF_HDR_SIZE];	/* "regf" */

	
	
	if ( !(rb = (REGF_FILE*)malloc( sizeof(REGF_FILE) )) ) {
		fprintf(stderr, "ERROR allocating memory\n");
		return NULL;
	}

	if ( !(rb->fd = open(filename, flags, mode)) == -1 ) {
		fprintf( stderr, "regfio_open: failure to open %s (%s)\n", filename, strerror(errno));
		regfio_close( rb );
		return NULL;
	}
	
	/* handle file creation here */
	
#if 0	/* skip for now */
	if ( flags & (O_CREAT|O_TRUNC) ) {
		;;		
	}
#endif
		

	/* read in regf block here */
	
	num_bytes = returned = 0;
	while ( num_bytes < REGF_BLOCKSIZE ) {
		if ( (returned = read( rb->fd, buffer+num_bytes, REGF_BLOCKSIZE-num_bytes )) == -1 ) {
			fprintf( stderr, "ERROR: read() failed (%s)\n", strerror(errno) );
			regfio_close( rb );
			return NULL;
		}
		if ( (returned == 0) && (num_bytes < REGF_BLOCKSIZE) ) {
			fprintf(stderr, "not a vald registry file ?\n" );
			regfio_close( rb );
			return NULL;
		}	
		
		num_bytes += returned;
	}

	/* check header */
		
	memcpy( header, buffer, REGF_HDR_SIZE );
	
	if ( strncmp( header, "regf", REGF_HDR_SIZE ) != 0 ) {
		fprintf(stderr, "invalid header\n" );
		regfio_close( rb );
		return NULL;
	}
	
	rb->data_offset    = IVAL( buffer, 0x24 );
	rb->last_block     = IVAL( buffer, 0x28 );
	
	/* verify the checksum */
	
	xor_value = x = 0;
	for ( i=0; i<0x000001FB; i+=4 ) {
		x = IVAL(buffer, i );
		xor_value ^= x;
	}
	
	rb->checksum = IVAL( buffer, 0x000001FC );
	if ( rb->checksum != xor_value ) {
		fprintf(stderr, "invalid checksum\n" );
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
	free( r );

	return close( fd );
}


