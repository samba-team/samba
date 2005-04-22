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

static BOOL prs_hbin_block( const char *desc, prs_struct *ps, int depth, REGF_HBIN *hbin )
{
	prs_debug(ps, depth, desc, "prs_regf_block");
	depth++;
	
	if ( !prs_uint8s( True, "header", ps, depth, hbin->header, sizeof( hbin->header )) )
		return False;

	if ( !prs_uint32( "first_hbin_off", ps, depth, &hbin->first_hbin_off ))
		return False;
	if ( !prs_uint32( "next_hbin_off", ps, depth, &hbin->next_hbin_off ))
		return False;
		
	if ( !prs_set_offset( ps, 0x001c ) )
		return False;
	if ( !prs_uint32( "block_size", ps, depth, &hbin->block_size ))
		return False;

	if ( !prs_set_offset( ps, 0x0020 ) )
		return False;
	if ( !prs_uint32( "data_size", ps, depth, &hbin->data_size ))
		return False;

	return True;
}

/*******************************************************************
*******************************************************************/

static BOOL prs_nk_rec( const char *desc, prs_struct *ps, int depth, REGF_NK_REC *nk )
{
	uint16 class_length, name_length;
	uint32 start;

	nk->hbin_off = prs_offset( ps );
	start = nk->hbin_off;
	
	prs_debug(ps, depth, desc, "prs_nk_rec");
	depth++;
	
	if ( !prs_uint8s( True, "header", ps, depth, nk->header, sizeof( nk->header )) )
		return False;
		
	if ( !prs_uint16( "key_type", ps, depth, &nk->key_type ))
		return False;
	if ( !smb_io_time( "mtime", &nk->mtime, ps, depth ))
		return False;
		
	if ( !prs_set_offset( ps, start+0x0010 ) )
		return False;
	if ( !prs_uint32( "parent_off", ps, depth, &nk->parent_off ))
		return False;
	if ( !prs_uint32( "num_subkeys", ps, depth, &nk->num_subkeys ))
		return False;
		
	if ( !prs_set_offset( ps, start+0x001c ) )
		return False;
	if ( !prs_uint32( "subkeys_off", ps, depth, &nk->subkeys_off ))
		return False;
		
	if ( !prs_set_offset( ps, start+0x0024 ) )
		return False;
	if ( !prs_uint32( "num_values", ps, depth, &nk->num_values ))
		return False;
	if ( !prs_uint32( "values_off", ps, depth, &nk->values_off ))
		return False;
	if ( !prs_uint32( "sk_off", ps, depth, &nk->sk_off ))
		return False;
	if ( !prs_uint32( "classname_off", ps, depth, &nk->classname_off ))
		return False;

	if ( !prs_set_offset( ps, start+0x0048 ) )
		return False;
	if ( !prs_uint16( "name_length", ps, depth, &name_length ))
		return False;
	if ( !prs_uint16( "class_length", ps, depth, &class_length ))
		return False;	
		
	if ( class_length ) {
		;;
	}
	
	if ( name_length ) {
		nk->keyname = PRS_ALLOC_MEM( ps, char, name_length+1 );
		if ( !prs_uint8s( True, "name", ps, depth, nk->keyname, name_length) )
			return False;
		nk->keyname[name_length] = '\0';
	}

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
	uint32 checksum;
	
	prs_init( &ps, REGF_BLOCKSIZE, file->mem_ctx, UNMARSHALL );
	
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
*******************************************************************/

static REGF_HBIN* read_hbin_block( REGF_FILE *file, off_t offset )
{
	REGF_HBIN *hbin;
	
	if ( !(hbin = (REGF_HBIN*)malloc(sizeof(REGF_HBIN)) ) ) 
		return NULL;
	ZERO_STRUCTP( hbin );
	
	prs_init( &hbin->ps, REGF_BLOCKSIZE, file->mem_ctx, UNMARSHALL );
	
	/* an offset of 0 means grab the first hbin block */
	
	if ( offset == 0 )
		offset = REGF_BLOCKSIZE;
	
	if ( read_block( &hbin->ps, offset, file->fd ) == -1 )
		return False;
	
	if ( !prs_hbin_block( "hbin", &hbin->ps, 0, hbin ) )
		return False;	

	if ( !prs_set_offset( &hbin->ps, file->data_offset+HBIN_HDR_SIZE ) )
		return False;
	
	return hbin;
}

/*******************************************************************
*******************************************************************/

static BOOL prs_hash_rec( const char *desc, prs_struct *ps, int depth, REGF_HASH_REC *hash )
{
	prs_debug(ps, depth, desc, "prs_hash_rec");
	depth++;

	if ( !prs_uint32( "nk_off", ps, depth, &hash->nk_off ))
		return False;
	if ( !prs_uint8s( True, "keycheck", ps, depth, hash->keycheck, sizeof( hash->keycheck )) )
		return False;
	
	return True;
}

/*******************************************************************
*******************************************************************/

static BOOL prs_lf_records( const char *desc, prs_struct *ps, int depth, REGF_NK_REC *nk )
{
	int i;
	REGF_LF_REC *lf = &nk->subkeys;

	prs_debug(ps, depth, desc, "prs_lf_records");
	depth++;

	/* check if we have anything to do first */
	
	if ( nk->num_subkeys == 0 )
		return True;

	/* move the LF record */

	if ( !prs_set_offset( ps, nk->subkeys_off+HBIN_HDR_SIZE ) )
		return False;

	
	if ( !prs_uint8s( True, "header", ps, depth, lf->header, sizeof( lf->header )) )
		return False;
		
	if ( !prs_uint16( "num_keys", ps, depth, &lf->num_keys))
		return False;

	if ( !(lf->hashes = PRS_ALLOC_MEM( ps, REGF_HASH_REC, lf->num_keys )) )
		return False;

	for ( i=0; i<lf->num_keys; i++ ) {
		if ( !prs_hash_rec( "hash_rec", ps, depth, &lf->hashes[i] ) )
			return False;
	}

	return True;
}

/*******************************************************************
*******************************************************************/

static BOOL prs_vk_rec( const char *desc, prs_struct *ps, int depth, REGF_VK_REC *vk )
{
	uint32 offset;
	uint16 name_length;

	prs_debug(ps, depth, desc, "prs_vk_rec");
	depth++;

	if ( !prs_uint8s( True, "header", ps, depth, vk->header, sizeof( vk->header )) )
		return False;

	if ( !prs_uint16( "name_length", ps, depth, &name_length ))
		return False;
	if ( !prs_uint32( "data_size", ps, depth, &vk->data_size ))
		return False;
	if ( !prs_uint32( "data_off", ps, depth, &vk->data_off ))
		return False;
	if ( !prs_uint32( "type", ps, depth, &vk->type))
		return False;
	if ( !prs_uint16( "flag", ps, depth, &vk->flag))
		return False;

	offset = prs_offset( ps );
	offset += 2;	/* skip 2 bytes */
	prs_set_offset( ps, offset );

	/* get the name */

	if ( vk->flag&VK_FLAG_NAME_PRESENT ) {

		if ( !(vk->valuename = PRS_ALLOC_MEM( ps, char, name_length+1 )))
			return False;
		if ( !prs_uint8s( True, "name", ps, depth, vk->valuename, name_length ) )
			return False;
	}

	/* get the data if necessary */

	if ( vk->data_size != 0 ) {
		BOOL charmode = vk->type & (REG_SZ|REG_MULTI_SZ);

		if ( !(vk->data = PRS_ALLOC_MEM( ps, uint8, vk->data_size) ) )
			return False;

		/* the data is stored in the offset if the size <= 4 */

		if ( vk->data_size > 4 ) {
			/* set the offset */
		
			if ( !(prs_set_offset( ps, vk->data_off+HBIN_HDR_SIZE )) )
				return False;

			if ( !prs_uint8s( charmode, "data", ps, depth, vk->data, vk->data_size) )
				return False;
		}
		else {
			SIVAL( vk->data, 0, vk->data_off );
		}
		
	}

	return True;
}

/*******************************************************************
*******************************************************************/

static BOOL prs_vk_records( const char *desc, prs_struct *ps, int depth, REGF_NK_REC *nk )
{
	int i;

	prs_debug(ps, depth, desc, "prs_vk_records");
	depth++;
	
	/* check if we have anything to do first */
	
	if ( nk->num_values == 0 )
		return True;
		
	if ( !(nk->values = PRS_ALLOC_MEM( ps, REGF_VK_REC, nk->num_values ) ) )
		return False;
	
	if ( !prs_set_offset( ps, nk->values_off+HBIN_HDR_SIZE) )
		return False;
		
	for ( i=0; i<nk->num_values; i++ ) {
		if ( !prs_uint32( "vk_off", ps, depth, &nk->values[i].hbin_off ) )
			return False;
	}

	for ( i=0; i<nk->num_values; i++ ) {
		if ( !prs_set_offset( ps, nk->values[i].hbin_off+HBIN_HDR_SIZE ) )
			return False;
		if ( !prs_vk_rec( "vk_rec", ps, depth, &nk->values[i] ) )
			return False;
	}

	return True;
}

/*******************************************************************
*******************************************************************/

static BOOL prs_key( REGF_HBIN *hbin, REGF_NK_REC *nk )
{
	int depth = 0;
	
	prs_debug(&hbin->ps, depth, "", "fetch_key");
	depth++;
	
	/* get the initial nk record */
	
	if ( !prs_nk_rec( "nk_rec", &hbin->ps, depth, nk ))
		return False;
			
	/* we now need to fill in the subkeys, values, and acls */
		
	if ( !prs_vk_records( "vk_rec", &hbin->ps, depth, nk ))
		return False;
	if ( !prs_lf_records( "lf_rec", &hbin->ps, depth, nk ))
		return False;
#if 0
	if ( !prs_sk_record( "sk_rec", &hbin->ps, depth, nk ))
		return False;
#endif
		
	return True;
}

/*******************************************************************
*******************************************************************/

REGF_NK_REC* regfio_next_key( REGF_FILE *file )
{
	char hdr[2];
	uint32 curr_off;
	REGF_HBIN *hbin = file->current_hbin;
	REGF_NK_REC *nk;

	/* peek at the next 2 bytes to get the header string */

	curr_off = prs_offset( &hbin->ps );
	if ( !prs_uint8s( True, "header", &hbin->ps, 0, hdr, sizeof( hdr )) )
		return False;
	prs_set_offset( &hbin->ps, curr_off );

	if ( !(nk = PRS_ALLOC_MEM( &hbin->ps, REGF_NK_REC, 1 )) )
		return NULL;

	/* compare the header strings */

	if ( strncmp( "nk", hdr, sizeof(hdr)) ) {
		/* fail if we are not at the beginning of another key */
		DEBUG(0,("regfio_next_key: dead end.  no nk_rec ready to process\n"));
		return NULL;
	}

	if ( !prs_key( hbin, nk) )
		return NULL;
				
	return nk;

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
	ZERO_STRUCTP( rb );
	rb->fd = -1;
	
	if ( !(rb->mem_ctx = talloc_init( "read_regf_block" )) ) {
		regfio_close( rb );
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
	
	if ( !(rb->current_hbin = read_hbin_block( rb, 0x0 )) ) {
		DEBUG(0,("regfio_open: Failed to read first hbin block\n"));
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


