/* 
 *  Unix SMB/CIFS implementation.
 *  RPC Pipe client / server routines
 *  Copyright (C) Marcin Krzysztof Porwit    2005,
 *  Copyright (C) Brian Moran                2005,
 *  Copyright (C) Gerald (Jerry) Carter      2005.
 *  
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include "includes.h"

#undef  DBGC_CLASS
#define DBGC_CLASS DBGC_RPC_SRV


typedef struct {
	pstring logname;	/* rather than alloc on the fly what we need... (memory is cheap now) */
	pstring tdbfname;
	TDB_CONTEXT *log_tdb;	/* the pointer to the TDB_CONTEXT */
} EventlogTDBInfo;

static int nlogs;
static EventlogTDBInfo *ttdb = NULL;
static TALLOC_CTX *mem_ctx = NULL;

typedef struct {
	char *logname;
	char *servername;
	uint32 num_records;
	uint32 oldest_entry;
	uint32 flags;
} EventlogInfo;



#if 0 /* UNUSED */
/********************************************************************
 ********************************************************************/
 
void test_eventlog_tdb( TDB_CONTEXT * the_tdb )
{
	Eventlog_entry ee;

	int i = 0;

	memset( &ee, 0, sizeof( Eventlog_entry ) );

	if ( !the_tdb )
		return;

	for ( i = 0; i < 100; i++ ) {
		ee.record.length = sizeof( ee.record );
		memset( &ee.data_record, 0, sizeof( ee.data_record ) );
		ee.record.reserved1 = 0xBEEFDEAD;
		ee.record.record_number = 1000 - i;	/* should get substituted */
		ee.record.time_generated = 0;
		ee.record.time_written = 0;
		ee.record.event_id = 500;
		ee.record.event_type = 300;
		ee.record.num_strings = 0;
		ee.record.event_category = 0;
		ee.record.reserved2 = ( i << 8 ) | i;
		ee.record.closing_record_number = -1;
		ee.record.string_offset = 0;
		ee.record.user_sid_length = 0;
		ee.record.user_sid_offset = 0;
		ee.record.data_length = 0;
		ee.record.data_offset = 0;

		rpcstr_push( ( void * ) ( ee.data_record.source_name ),
			     "SystemLog",
			     sizeof( ee.data_record.source_name ),
			     STR_TERMINATE );
		ee.data_record.source_name_len =
			( strlen_w( ee.data_record.source_name ) * 2 ) + 2;

		rpcstr_push( ( void * ) ( ee.data_record.computer_name ),
			     "DMLINUX",
			     sizeof( ee.data_record.computer_name ),
			     STR_TERMINATE );

		ee.data_record.computer_name_len =
			( strlen_w( ee.data_record.computer_name ) * 2 ) + 2;

		write_eventlog_tdb( the_tdb, &ee );
	}
}
#endif /* UNUSED */

/********************************************************************
 ********************************************************************/

static void refresh_eventlog_tdb_table( void )
{
	const char **elogs = lp_eventlog_list(  );
	int i, j;

	if ( !elogs )
		return;

	if ( !mem_ctx ) {
		mem_ctx = talloc_init( "refresh_eventlog_tdb_table" );
	}

	if ( !mem_ctx ) {
		DEBUG( 1, ( "Can't allocate memory\n" ) );
		return;
	}

	/* count them */
	for ( i = 0; elogs[i]; i++ ) {
	}
	/* number of logs in i */
	DEBUG( 10, ( "Number of eventlogs %d\n", i ) );
	/* check to see if we need to adjust our tables */

	if ( ( ttdb != NULL ) ) {
		if ( i != nlogs ) {
			/* refresh the table, by closing and reconstructing */
			DEBUG( 10, ( "Closing existing table \n" ) );
			for ( j = 0; j < nlogs; j++ ) {
				tdb_close( ttdb[j].log_tdb );
			}
			TALLOC_FREE( ttdb );
			ttdb = NULL;
		} else {	/* i == nlogs */

			for ( j = 0; j < nlogs; j++ ) {
				if ( StrCaseCmp( ttdb[j].logname, elogs[i] ) ) {
					/* something changed, have to discard */
					DEBUG( 10,
					       ( "Closing existing table \n" ) );
					for ( j = 0; j < nlogs; j++ ) {
						tdb_close( ttdb[j].log_tdb );
					}
					TALLOC_FREE( ttdb );
					ttdb = NULL;
					break;
				}
			}
		}
	}

	/* note that this might happen because of above */
	if ( ( i > 0 ) && ( ttdb == NULL ) ) {
		/* alloc the room */
		DEBUG( 10, ( "Creating the table\n" ) );
		ttdb = TALLOC( mem_ctx, sizeof( EventlogTDBInfo ) * i );
		if ( !ttdb ) {
			DEBUG( 10,
			       ( "Can't allocate table for tdb handles \n" ) );
			return;
		}
		for ( j = 0; j < i; j++ ) {
			pstrcpy( ttdb[j].tdbfname,
				 lock_path( mk_tdbfilename
					    ( ttdb[j].tdbfname,
					      ( char * ) elogs[j],
					      sizeof( pstring ) ) ) );
			pstrcpy( ttdb[j].logname, elogs[j] );
			DEBUG( 10, ( "Opening tdb for %s\n", elogs[j] ) );
			ttdb[j].log_tdb =
				open_eventlog_tdb( ttdb[j].tdbfname );
		}
	}
	nlogs = i;
}

/********************************************************************
 ********************************************************************/

TDB_CONTEXT *tdb_of( char *eventlog_name )
{
	int i;

	if ( !eventlog_name )
		return NULL;

	if ( !ttdb ) {
		DEBUG( 10, ( "Refreshing list of eventlogs\n" ) );
		refresh_eventlog_tdb_table(  );

		if ( !ttdb ) {
			DEBUG( 10,
			       ( "eventlog tdb table is NULL after a refresh!\n" ) );
			return NULL;
		}
	}

	DEBUG( 10, ( "Number of eventlogs %d\n", nlogs ) );

	for ( i = 0; i < nlogs; i++ ) {
		if ( strequal( eventlog_name, ttdb[i].logname ) ) 
			return ttdb[i].log_tdb;
	}

	return NULL;
}


/********************************************************************
  For the given tdb, get the next eventlog record into the passed 
  Eventlog_entry.  returns NULL if it can't get the record for some reason.
 ********************************************************************/

Eventlog_entry *get_eventlog_record( prs_struct * ps, TDB_CONTEXT * tdb,
				     int recno, Eventlog_entry * ee )
{
	TDB_DATA ret, key;

	int srecno;
	int reclen;
	int len;
	uint8 *rbuff;

	pstring *wpsource, *wpcomputer, *wpsid, *wpstrs, *puserdata;

	key.dsize = sizeof( int32 );
	rbuff = NULL;

	srecno = recno;
	key.dptr = ( char * ) &srecno;

	ret = tdb_fetch( tdb, key );

	if ( ret.dsize == 0 ) {
		DEBUG( 8,
		       ( "Can't find a record for the key, record %d\n",
			 recno ) );
		return NULL;
	}

	len = tdb_unpack( ret.dptr, ret.dsize, "d", &reclen );

	DEBUG( 10, ( "Unpacking record %d, size is %d\n", srecno, len ) );

	if ( !len )
		return NULL;

	/* ee = PRS_ALLOC_MEM(ps, Eventlog_entry, 1); */

	if ( !ee )
		return NULL;

	len = tdb_unpack( ret.dptr, ret.dsize, "ddddddwwwwddddddBBdBBBd",
			  &ee->record.length, &ee->record.reserved1,
			  &ee->record.record_number,
			  &ee->record.time_generated,
			  &ee->record.time_written, &ee->record.event_id,
			  &ee->record.event_type, &ee->record.num_strings,
			  &ee->record.event_category, &ee->record.reserved2,
			  &ee->record.closing_record_number,
			  &ee->record.string_offset,
			  &ee->record.user_sid_length,
			  &ee->record.user_sid_offset,
			  &ee->record.data_length, &ee->record.data_offset,
			  &ee->data_record.source_name_len, &wpsource,
			  &ee->data_record.computer_name_len, &wpcomputer,
			  &ee->data_record.sid_padding,
			  &ee->record.user_sid_length, &wpsid,
			  &ee->data_record.strings_len, &wpstrs,
			  &ee->data_record.user_data_len, &puserdata,
			  &ee->data_record.data_padding );
	DEBUG( 10,
	       ( "Read record %d, len in tdb was %d\n",
		 ee->record.record_number, len ) );

	/* have to do the following because the tdb_unpack allocs a buff, stuffs a pointer to the buff
	   into it's 2nd argment for 'B' */

	if ( wpcomputer )
		memcpy( ee->data_record.computer_name, wpcomputer,
			ee->data_record.computer_name_len );
	if ( wpsource )
		memcpy( ee->data_record.source_name, wpsource,
			ee->data_record.source_name_len );

	if ( wpsid )
		memcpy( ee->data_record.sid, wpsid,
			ee->record.user_sid_length );
	if ( wpstrs )
		memcpy( ee->data_record.strings, wpstrs,
			ee->data_record.strings_len );

	/* note that userdata is a pstring */
	if ( puserdata )
		memcpy( ee->data_record.user_data, puserdata,
			ee->data_record.user_data_len );

	SAFE_FREE( wpcomputer );
	SAFE_FREE( wpsource );
	SAFE_FREE( wpsid );
	SAFE_FREE( wpstrs );
	SAFE_FREE( puserdata );

	DEBUG( 10, ( "get_eventlog_record: read back %d\n", len ) );
	DEBUG( 10,
	       ( "get_eventlog_record: computer_name %d is ",
		 ee->data_record.computer_name_len ) );
	SAFE_FREE( ret.dptr );
	return ee;
}

/********************************************************************
 ********************************************************************/

static void free_eventlog_info( void *ptr )
{
	TALLOC_FREE( ptr );
}

/********************************************************************
 ********************************************************************/

static EventlogInfo *find_eventlog_info_by_hnd( pipes_struct * p,
						POLICY_HND * handle )
{
	EventlogInfo *info;

	if ( !find_policy_by_hnd( p, handle, ( void ** ) &info ) ) {
		DEBUG( 2,
		       ( "find_eventlog_info_by_hnd: eventlog not found.\n" ) );
		return NULL;
	}

	return info;
}

/********************************************************************
 note that this can only be called AFTER the table is constructed, 
 since it uses the table to find the tdb handle
 ********************************************************************/

static BOOL sync_eventlog_params( const char *elogname )
{
	pstring path;
	uint32 uiMaxSize;
	uint32 uiRetention;
	REGISTRY_KEY *keyinfo;
	REGISTRY_VALUE *val;
	REGVAL_CTR *values;
	WERROR wresult;
	TDB_CONTEXT *the_tdb;

	the_tdb = tdb_of( ( char * ) elogname );

	DEBUG( 4, ( "sync_eventlog_params with %s\n", elogname ) );

	if ( !the_tdb ) {
		DEBUG( 4, ( "Can't open tdb for %s\n", elogname ) );
		return False;
	}
	/* set resonable defaults.  512Kb on size and 1 week on time */

	uiMaxSize = 0x80000;
	uiRetention = 604800;

	/* the general idea is to internally open the registry 
	   key and retreive the values.  That way we can continue 
	   to use the same fetch/store api that we use in 
	   srv_reg_nt.c */

	pstr_sprintf( path, "%s/%s", KEY_EVENTLOG, elogname );

	wresult =
		regkey_open_internal( &keyinfo, path, get_root_nt_token(  ),
				      REG_KEY_READ );

	if ( !W_ERROR_IS_OK( wresult ) ) {
		DEBUG( 4,
		       ( "sync_eventlog_params: Failed to open key [%s] (%s)\n",
			 path, dos_errstr( wresult ) ) );
		return False;
	}

	if ( !( values = TALLOC_ZERO_P( keyinfo, REGVAL_CTR ) ) ) {
		TALLOC_FREE( keyinfo );
		DEBUG( 0, ( "control_eventlog_hook: talloc() failed!\n" ) );

		return False;
	}
	fetch_reg_values( keyinfo, values );

	if ( ( val = regval_ctr_getvalue( values, "Retention" ) ) != NULL )
		uiRetention = IVAL( regval_data_p( val ), 0 );

	if ( ( val = regval_ctr_getvalue( values, "MaxSize" ) ) != NULL )
		uiMaxSize = IVAL( regval_data_p( val ), 0 );

	TALLOC_FREE( keyinfo );

	tdb_store_int32( the_tdb, VN_maxsize, uiMaxSize );
	tdb_store_int32( the_tdb, VN_retention, uiRetention );

	return True;
}

/********************************************************************
 ********************************************************************/

static BOOL open_eventlog_hook( EventlogInfo * info )
{
	return True;
}

/********************************************************************
********************************************************************/

/**
 * Callout to get the number of records in the specified event log
 * 
 *   smbrun calling convention --
 *     INPUT: <get_num_records_cmd> <log name> <policy handle>
 *     OUTPUT: A single line with a single integer containing the number of
 *             entries in the log. If there are no entries in the log, return 0.
 */


static BOOL get_num_records_hook( EventlogInfo * info )
{

	TDB_CONTEXT *the_tdb = NULL;
	int next_record;
	int oldest_record;


	the_tdb = tdb_of( info->logname );

	if ( !the_tdb ) {
		DEBUG( 10, ( "Can't find tdb for %s\n", info->logname ) );
		info->num_records = 0;
		return False;
	}

	/* lock */
	tdb_lock_bystring( the_tdb, VN_next_record, 1 );


	/* read */
	next_record = tdb_fetch_int32( the_tdb, VN_next_record );
	oldest_record = tdb_fetch_int32( the_tdb, VN_oldest_entry );



	DEBUG( 8,
	       ( "Oldest Record %d Next Record %d\n", oldest_record,
		 next_record ) );

	info->num_records = ( next_record - oldest_record );
	info->oldest_entry = oldest_record;
	tdb_unlock_bystring( the_tdb, VN_next_record );


	return True;


}

/********************************************************************
 ********************************************************************/

/**
 * Callout to find the oldest record in the log
 * 
 *   smbrun calling convention --
 *     INPUT: <oldest_entry_cmd> <log name> <policy handle>
 *     OUTPUT: If there are entries in the event log, the index of the
 *             oldest entry. Must be 1 or greater.
 *             If there are no entries in the log, returns a 0
 */

static BOOL get_oldest_entry_hook( EventlogInfo * info )
{

	/* it's the same thing */
	return get_num_records_hook( info );
}


/********************************************************************
 ********************************************************************/

/**
 * Callout to close the specified event log
 * 
 *   smbrun calling convention --
 *     INPUT: <close_cmd> <log name> <policy handle>
 *     OUTPUT: the string "SUCCESS" if the command succeeded
 *             no such string if there was a failure.
 */

static BOOL close_eventlog_hook( EventlogInfo * info )
{

	return True;
}

/********************************************************************
 ********************************************************************/

static Eventlog_entry *read_package_entry( prs_struct * ps,
					   EVENTLOG_Q_READ_EVENTLOG * q_u,
					   EVENTLOG_R_READ_EVENTLOG * r_u,
					   Eventlog_entry * entry )
{
	uint8 *offset;
	Eventlog_entry *ee_new = NULL;

	ee_new = PRS_ALLOC_MEM( ps, Eventlog_entry, 1 );
	if ( ee_new == NULL ) {
		return NULL;
	}

	entry->data_record.sid_padding =
		( ( 4 -
		    ( ( entry->data_record.source_name_len +
			entry->data_record.computer_name_len ) % 4 ) ) % 4 );
	entry->data_record.data_padding =
		( 4 -
		  ( ( entry->data_record.strings_len +
		      entry->data_record.user_data_len ) % 4 ) ) % 4;
	entry->record.length = sizeof( Eventlog_record );
	entry->record.length += entry->data_record.source_name_len;
	entry->record.length += entry->data_record.computer_name_len;
	if ( entry->record.user_sid_length == 0 ) {
		/* Should not pad to a DWORD boundary for writing out the sid if there is
		   no SID, so just propagate the padding to pad the data */
		entry->data_record.data_padding +=
			entry->data_record.sid_padding;
		entry->data_record.sid_padding = 0;
	}
	DEBUG( 10,
	       ( "sid_padding is [%d].\n", entry->data_record.sid_padding ) );
	DEBUG( 10,
	       ( "data_padding is [%d].\n",
		 entry->data_record.data_padding ) );

	entry->record.length += entry->data_record.sid_padding;
	entry->record.length += entry->record.user_sid_length;
	entry->record.length += entry->data_record.strings_len;
	entry->record.length += entry->data_record.user_data_len;
	entry->record.length += entry->data_record.data_padding;
	/* need another copy of length at the end of the data */
	entry->record.length += sizeof( entry->record.length );
	DEBUG( 10,
	       ( "entry->record.length is [%d].\n", entry->record.length ) );
	entry->data =
		PRS_ALLOC_MEM( ps, uint8,
			       entry->record.length -
			       sizeof( Eventlog_record ) -
			       sizeof( entry->record.length ) );
	if ( entry->data == NULL ) {
		return NULL;
	}
	offset = entry->data;
	memcpy( offset, &( entry->data_record.source_name ),
		entry->data_record.source_name_len );
	offset += entry->data_record.source_name_len;
	memcpy( offset, &( entry->data_record.computer_name ),
		entry->data_record.computer_name_len );
	offset += entry->data_record.computer_name_len;
	/* SID needs to be DWORD-aligned */
	offset += entry->data_record.sid_padding;
	entry->record.user_sid_offset =
		sizeof( Eventlog_record ) + ( offset - entry->data );
	memcpy( offset, &( entry->data_record.sid ),
		entry->record.user_sid_length );
	offset += entry->record.user_sid_length;
	/* Now do the strings */
	entry->record.string_offset =
		sizeof( Eventlog_record ) + ( offset - entry->data );
	memcpy( offset, &( entry->data_record.strings ),
		entry->data_record.strings_len );
	offset += entry->data_record.strings_len;
	/* Now do the data */
	entry->record.data_length = entry->data_record.user_data_len;
	entry->record.data_offset =
		sizeof( Eventlog_record ) + ( offset - entry->data );
	memcpy( offset, &( entry->data_record.user_data ),
		entry->data_record.user_data_len );
	offset += entry->data_record.user_data_len;

	memcpy( &( ee_new->record ), &entry->record,
		sizeof( Eventlog_record ) );
	memcpy( &( ee_new->data_record ), &entry->data_record,
		sizeof( Eventlog_data_record ) );
	ee_new->data = entry->data;

	return ee_new;
}

/********************************************************************
 ********************************************************************/

static BOOL add_record_to_resp( EVENTLOG_R_READ_EVENTLOG * r_u,
				Eventlog_entry * ee_new )
{
	Eventlog_entry *insert_point;

	insert_point = r_u->entry;

	if ( NULL == insert_point ) {
		r_u->entry = ee_new;
		ee_new->next = NULL;
	} else {
		while ( ( NULL != insert_point->next ) ) {
			insert_point = insert_point->next;
		}
		ee_new->next = NULL;
		insert_point->next = ee_new;
	}
	r_u->num_records++;
	r_u->num_bytes_in_resp += ee_new->record.length;

	return True;
}

/********************************************************************
 ********************************************************************/

/**
 * Callout to clear (and optionally backup) a specified event log
 *
 *   smbrun calling convention --
 *     INPUT:  <clear_eventlog_cmd> <log name> <policy handle>
 *     OUTPUT: A single line with the string "SUCCESS" if the command succeeded.
 *             Otherwise it is assumed to have failed
 *
 *     INPUT:  <clear_eventlog_cmd> <log name> <backup file> <policy handle>
 *     OUTPUT: A single line with the string "SUCCESS" if the command succeeded.
 *             Otherwise it is assumed to have failed
 *             The given log is copied to that location on the server. See comments for
 *               eventlog_io_q_clear_eventlog for info about odd file name behavior
 */
static BOOL clear_eventlog_hook( EventlogInfo * info,
				 pstring backup_file_name )
{

	int i;


	if ( !info )
		return False;
	DEBUG( 3, ( "There are %d event logs\n", nlogs ) );
	for ( i = 0; i < nlogs; i++ ) {
		DEBUG( 3,
		       ( "Comparing Eventlog %s,  %s\n", info->logname,
			 ttdb[i].logname ) );
		if ( !StrCaseCmp( info->logname, ttdb[i].logname ) ) {
			/* close the current one, reinit */
			tdb_close( ttdb[i].log_tdb );
			DEBUG( 3,
			       ( "Closing Eventlog %s, file-on-disk %s\n",
				 info->logname, ttdb[i].tdbfname ) );
			ttdb[i].log_tdb =
				init_eventlog_tdb( ttdb[i].tdbfname );
			return True;
		}
	}

	return False;		/* not found */
	/* TODO- do something with the backup file name */

}

/*******************************************************************
 *******************************************************************/

static int eventlog_size( char *eventlog_name )
{
	TDB_CONTEXT *tdb;

	if ( !eventlog_name )
		return 0;
	tdb = tdb_of( eventlog_name );
	if ( !tdb )
		return 0;
	return eventlog_tdb_size( tdb, NULL, NULL );
}

/********************************************************************
 ********************************************************************/

WERROR _eventlog_open_eventlog( pipes_struct * p,
				EVENTLOG_Q_OPEN_EVENTLOG * q_u,
				EVENTLOG_R_OPEN_EVENTLOG * r_u )
{
	EventlogInfo *info = NULL;
	fstring str;

	if ( !( info = TALLOC_ZERO_P( NULL, EventlogInfo ) ) )
		return WERR_NOMEM;

	fstrcpy( str, global_myname(  ) );
	if ( q_u->servername.string ) {
		rpcstr_pull( str, q_u->servername.string->buffer,
			     sizeof( str ),
			     q_u->servername.string->uni_str_len * 2, 0 );
	}

	info->servername = talloc_strdup( info, str );

	fstrcpy( str, "Application" );
	if ( q_u->logname.string ) {
		rpcstr_pull( str, q_u->logname.string->buffer,
			     sizeof( str ),
			     q_u->logname.string->uni_str_len * 2, 0 );
	}

	info->logname = talloc_strdup( info, str );

	DEBUG( 1,
	       ( "Size of %s is %d\n", info->logname,
		 eventlog_size( info->logname ) ) );



	DEBUG( 10,
	       ( "_eventlog_open_eventlog: Using [%s] as the server name.\n",
		 info->servername ) );
	DEBUG( 10,
	       ( "_eventlog_open_eventlog: Using [%s] as the source log file.\n",
		 info->logname ) );


	if ( !create_policy_hnd
	     ( p, &r_u->handle, free_eventlog_info, ( void * ) info ) ) {
		free_eventlog_info( info );
		return WERR_NOMEM;
	}

	if ( !open_eventlog_hook( info ) ) {
		close_policy_hnd( p, &r_u->handle );
		return WERR_BADFILE;
	}

	sync_eventlog_params( info->logname );
	prune_eventlog( tdb_of( info->logname ) );

	return WERR_OK;
}

/********************************************************************
 ********************************************************************/

WERROR _eventlog_clear_eventlog( pipes_struct * p,
				 EVENTLOG_Q_CLEAR_EVENTLOG * q_u,
				 EVENTLOG_R_CLEAR_EVENTLOG * r_u )
{
	EventlogInfo *info = find_eventlog_info_by_hnd( p, &q_u->handle );
	pstring backup_file_name;

	pstrcpy( backup_file_name, "" );

	if ( q_u->backupfile.string )
		unistr2_to_ascii( backup_file_name, q_u->backupfile.string,
				  sizeof( backup_file_name ) );

	DEBUG( 10,
	       ( "_eventlog_clear_eventlog: Using [%s] as the backup file name for log [%s].",
		 backup_file_name, info->logname ) );

	if ( !( clear_eventlog_hook( info, backup_file_name ) ) )
		return WERR_BADFILE;

	return WERR_OK;
}

/********************************************************************
 ********************************************************************/

WERROR _eventlog_close_eventlog( pipes_struct * p,
				 EVENTLOG_Q_CLOSE_EVENTLOG * q_u,
				 EVENTLOG_R_CLOSE_EVENTLOG * r_u )
{
	EventlogInfo *info = find_eventlog_info_by_hnd( p, &q_u->handle );

	if ( !( close_eventlog_hook( info ) ) )
		return WERR_BADFILE;

	if ( !( close_policy_hnd( p, &q_u->handle ) ) ) {
		return WERR_BADFID;
	}

	return WERR_OK;
}

/********************************************************************
 ********************************************************************/

WERROR _eventlog_read_eventlog( pipes_struct * p,
				EVENTLOG_Q_READ_EVENTLOG * q_u,
				EVENTLOG_R_READ_EVENTLOG * r_u )
{
	EventlogInfo *info = find_eventlog_info_by_hnd( p, &q_u->handle );
	Eventlog_entry entry, *ee_new;

	uint32 num_records_read = 0;
	prs_struct *ps;
	int bytes_left, record_number;
	TDB_CONTEXT *the_tdb;


	info->flags = q_u->flags;
	ps = &p->out_data.rdata;


	bytes_left = q_u->max_read_size;
	the_tdb = tdb_of( info->logname );
	if ( !the_tdb ) {
		/* todo handle the error */

	}
	/* DEBUG(8,("Bytes left is %d\n",bytes_left)); */


	record_number = q_u->offset;

	while ( bytes_left > 0 ) {
		if ( get_eventlog_record
		     ( ps, the_tdb, record_number, &entry ) ) {
			DEBUG( 8,
			       ( "Retrieved record %d\n", record_number ) );
			/* Now see if there is enough room to add */
			if ( ( ee_new =
			       read_package_entry( ps, q_u, r_u,
						   &entry ) ) == NULL ) {
				return WERR_NOMEM;

			}

			if ( r_u->num_bytes_in_resp + ee_new->record.length >
			     q_u->max_read_size ) {
				r_u->bytes_in_next_record =
					ee_new->record.length;
				/* response would be too big to fit in client-size buffer */
				bytes_left = 0;
				break;
			}
			add_record_to_resp( r_u, ee_new );
			bytes_left -= ee_new->record.length;
			ZERO_STRUCT( entry );
			num_records_read =
				r_u->num_records - num_records_read;
			DEBUG( 10,
			       ( "_eventlog_read_eventlog: read [%d] records for a total of [%d] records using [%d] bytes out of a max of [%d].\n",
				 num_records_read, r_u->num_records,
				 r_u->num_bytes_in_resp,
				 q_u->max_read_size ) );
		} else {
			DEBUG( 8, ( "get_eventlog_record returned NULL\n" ) );
			return WERR_NOMEM;	/* wrong error - but return one anyway */
		}


		if ( info->flags & EVENTLOG_FORWARDS_READ ) {
			record_number++;
		} else {
			record_number--;
		}

	}
	return WERR_OK;
}

/********************************************************************
 ********************************************************************/

WERROR _eventlog_get_oldest_entry( pipes_struct * p,
				   EVENTLOG_Q_GET_OLDEST_ENTRY * q_u,
				   EVENTLOG_R_GET_OLDEST_ENTRY * r_u )
{
	EventlogInfo *info = find_eventlog_info_by_hnd( p, &q_u->handle );

	if ( !( get_oldest_entry_hook( info ) ) )
		return WERR_BADFILE;

	r_u->oldest_entry = info->oldest_entry;

	return WERR_OK;
}

/********************************************************************
 ********************************************************************/

WERROR _eventlog_get_num_records( pipes_struct * p,
				  EVENTLOG_Q_GET_NUM_RECORDS * q_u,
				  EVENTLOG_R_GET_NUM_RECORDS * r_u )
{
	EventlogInfo *info = find_eventlog_info_by_hnd( p, &q_u->handle );

	if ( !( get_num_records_hook( info ) ) )
		return WERR_BADFILE;

	r_u->num_records = info->num_records;

	return WERR_OK;
}
