/* 
 *  Unix SMB/CIFS implementation.
 *  RPC Pipe client / server routines
 *  Copyright (C) Marcin Krzysztof Porwit    2005,
 *  Copyright (C) Brian Moran                2005,
 *  Copyright (C) Gerald (Jerry) Carter      2005.
 *  
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"

#undef  DBGC_CLASS
#define DBGC_CLASS DBGC_RPC_SRV

typedef struct {
	char *logname;
	ELOG_TDB *etdb;
	uint32 current_record;
	uint32 num_records;
	uint32 oldest_entry;
	uint32 flags;
	uint32 access_granted;
} EVENTLOG_INFO;

/********************************************************************
 ********************************************************************/

static void free_eventlog_info( void *ptr )
{
	EVENTLOG_INFO *elog = (EVENTLOG_INFO *)ptr;
	
	if ( elog->etdb )
		elog_close_tdb( elog->etdb, False );
	
	TALLOC_FREE( elog );
}

/********************************************************************
 ********************************************************************/

static EVENTLOG_INFO *find_eventlog_info_by_hnd( pipes_struct * p,
						POLICY_HND * handle )
{
	EVENTLOG_INFO *info;

	if ( !find_policy_by_hnd( p, handle, (void **)(void *)&info ) ) {
		DEBUG( 2,
		       ( "find_eventlog_info_by_hnd: eventlog not found.\n" ) );
		return NULL;
	}

	return info;
}

/********************************************************************
********************************************************************/

static bool elog_check_access( EVENTLOG_INFO *info, NT_USER_TOKEN *token )
{
	char *tdbname = elog_tdbname(talloc_tos(), info->logname );
	SEC_DESC *sec_desc;
	NTSTATUS status;
	
	if ( !tdbname ) 
		return False;
	
	/* get the security descriptor for the file */
	
	sec_desc = get_nt_acl_no_snum( info, tdbname );
	TALLOC_FREE( tdbname );
	
	if ( !sec_desc ) {
		DEBUG(5,("elog_check_access: Unable to get NT ACL for %s\n", 
			tdbname));
		return False;
	}
	
	/* root free pass */

	if ( geteuid() == sec_initial_uid() ) {
		DEBUG(5,("elog_check_access: using root's token\n"));
		token = get_root_nt_token();
	}

	/* run the check, try for the max allowed */
	
	status = se_access_check( sec_desc, token, MAXIMUM_ALLOWED_ACCESS,
		&info->access_granted);
		
	if ( sec_desc )
		TALLOC_FREE( sec_desc );
		
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(8,("elog_check_access: se_access_check() return %s\n",
			nt_errstr(status)));
		return False;
	}
	
	/* we have to have READ permission for a successful open */
	
	return ( info->access_granted & SA_RIGHT_FILE_READ_DATA );
}

/********************************************************************
 ********************************************************************/

static bool elog_validate_logname( const char *name )
{
	int i;
	const char **elogs = lp_eventlog_list();
	
	if (!elogs) {
		return False;
	}

	for ( i=0; elogs[i]; i++ ) {
		if ( strequal( name, elogs[i] ) )
			return True;
	}
	
	return False;
}

/********************************************************************
********************************************************************/

static bool get_num_records_hook( EVENTLOG_INFO * info )
{
	int next_record;
	int oldest_record;

	if ( !info->etdb ) {
		DEBUG( 10, ( "No open tdb for %s\n", info->logname ) );
		return False;
	}

	/* lock the tdb since we have to get 2 records */

	tdb_lock_bystring_with_timeout( ELOG_TDB_CTX(info->etdb), EVT_NEXT_RECORD, 1 );
	next_record = tdb_fetch_int32( ELOG_TDB_CTX(info->etdb), EVT_NEXT_RECORD);
	oldest_record = tdb_fetch_int32( ELOG_TDB_CTX(info->etdb), EVT_OLDEST_ENTRY);
	tdb_unlock_bystring( ELOG_TDB_CTX(info->etdb), EVT_NEXT_RECORD);

	DEBUG( 8,
	       ( "Oldest Record %d; Next Record %d\n", oldest_record,
		 next_record ) );

	info->num_records = ( next_record - oldest_record );
	info->oldest_entry = oldest_record;

	return True;
}

/********************************************************************
 ********************************************************************/

static bool get_oldest_entry_hook( EVENTLOG_INFO * info )
{
	/* it's the same thing */
	return get_num_records_hook( info );
}

/********************************************************************
 ********************************************************************/

static NTSTATUS elog_open( pipes_struct * p, const char *logname, POLICY_HND *hnd )
{
	EVENTLOG_INFO *elog;
	
	/* first thing is to validate the eventlog name */
	
	if ( !elog_validate_logname( logname ) )
		return NT_STATUS_OBJECT_PATH_INVALID;
	
	if ( !(elog = TALLOC_ZERO_P( NULL, EVENTLOG_INFO )) )
		return NT_STATUS_NO_MEMORY;
		
	elog->logname = talloc_strdup( elog, logname );
	
	/* Open the tdb first (so that we can create any new tdbs if necessary).
	   We have to do this as root and then use an internal access check 
	   on the file permissions since you can only have a tdb open once
	   in a single process */

	become_root();
	elog->etdb = elog_open_tdb( elog->logname, False );
	unbecome_root();

	if ( !elog->etdb ) {
		/* according to MSDN, if the logfile cannot be found, we should
		  default to the "Application" log */
	
		if ( !strequal( logname, ELOG_APPL ) ) {
		
			TALLOC_FREE( elog->logname );
			
			elog->logname = talloc_strdup( elog, ELOG_APPL );			

			/* do the access check */
			if ( !elog_check_access( elog, p->pipe_user.nt_user_token ) ) {
				TALLOC_FREE( elog );
				return NT_STATUS_ACCESS_DENIED;
			}
	
			become_root();
			elog->etdb = elog_open_tdb( elog->logname, False );
			unbecome_root();
		}	
		
		if ( !elog->etdb ) {
			TALLOC_FREE( elog );
			return NT_STATUS_ACCESS_DENIED;	/* ??? */		
		}
	}
	
	/* now do the access check.  Close the tdb if we fail here */

	if ( !elog_check_access( elog, p->pipe_user.nt_user_token ) ) {
		elog_close_tdb( elog->etdb, False );
		TALLOC_FREE( elog );
		return NT_STATUS_ACCESS_DENIED;
	}
	
	/* create the policy handle */
	
	if ( !create_policy_hnd
	     ( p, hnd, free_eventlog_info, ( void * ) elog ) ) {
		free_eventlog_info( elog );
		return NT_STATUS_NO_MEMORY;
	}

	/* set the initial current_record pointer */

	if ( !get_oldest_entry_hook( elog ) ) {
		DEBUG(3,("elog_open: Successfully opened eventlog but can't "
			"get any information on internal records!\n"));
	}	

	elog->current_record = elog->oldest_entry;

	return NT_STATUS_OK;
}

/********************************************************************
 ********************************************************************/

static NTSTATUS elog_close( pipes_struct *p, POLICY_HND *hnd )
{
        if ( !( close_policy_hnd( p, hnd ) ) ) {
                return NT_STATUS_INVALID_HANDLE;
        }

	return NT_STATUS_OK;
}

/*******************************************************************
 *******************************************************************/

static int elog_size( EVENTLOG_INFO *info )
{
	if ( !info || !info->etdb ) {
		DEBUG(0,("elog_size: Invalid info* structure!\n"));
		return 0;
	}

	return elog_tdb_size( ELOG_TDB_CTX(info->etdb), NULL, NULL );
}

/********************************************************************
  For the given tdb, get the next eventlog record into the passed
  Eventlog_entry.  returns NULL if it can't get the record for some reason.
 ********************************************************************/

static Eventlog_entry *get_eventlog_record(prs_struct *ps,
				TDB_CONTEXT *tdb,
				int recno)
{
	Eventlog_entry *ee = NULL;
	TDB_DATA ret, key;

	int32_t srecno;
	int32_t reclen;
	int len;

	char *wpsource = NULL;
	char *wpcomputer = NULL;
	char *wpsid = NULL;
	char *wpstrs = NULL;
	char *puserdata = NULL;

	key.dsize = sizeof(int32_t);

	srecno = recno;
	key.dptr = (unsigned char *)&srecno;

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

	ee = TALLOC_ARRAY(ps->mem_ctx, Eventlog_entry, 1);
	if (!ee) {
		return NULL;
	}
	ZERO_STRUCTP(ee);

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

	if (wpcomputer) {
		ee->data_record.computer_name = (smb_ucs2_t *)TALLOC_MEMDUP(
			ee, wpcomputer, ee->data_record.computer_name_len);
		if (!ee->data_record.computer_name) {
			TALLOC_FREE(ee);
			goto out;
		}
	}
	if (wpsource) {
		ee->data_record.source_name = (smb_ucs2_t *)TALLOC_MEMDUP(
			ee, wpsource, ee->data_record.source_name_len);
		if (!ee->data_record.source_name) {
			TALLOC_FREE(ee);
			goto out;
		}
	}

	if (wpsid) {
		ee->data_record.sid = (smb_ucs2_t *)TALLOC_MEMDUP(
			ee, wpsid, ee->record.user_sid_length);
		if (!ee->data_record.sid) {
			TALLOC_FREE(ee);
			goto out;
		}
	}
	if (wpstrs) {
		ee->data_record.strings = (smb_ucs2_t *)TALLOC_MEMDUP(
			ee, wpstrs, ee->data_record.strings_len);
		if (!ee->data_record.strings) {
			TALLOC_FREE(ee);
			goto out;
		}
	}

	if (puserdata) {
		ee->data_record.user_data = (char *)TALLOC_MEMDUP(
			ee, puserdata, ee->data_record.user_data_len);
		if (!ee->data_record.user_data) {
			TALLOC_FREE(ee);
			goto out;
		}
	}

  out:

	SAFE_FREE(wpcomputer);
	SAFE_FREE(wpsource);
	SAFE_FREE(wpsid);
	SAFE_FREE(wpstrs);
	SAFE_FREE(puserdata);

	DEBUG( 10, ( "get_eventlog_record: read back %d\n", len ) );
	DEBUG( 10,
	       ( "get_eventlog_record: computer_name %d is ",
		 ee->data_record.computer_name_len ) );
	SAFE_FREE(ret.dptr);
	return ee;
}

/********************************************************************
 note that this can only be called AFTER the table is constructed, 
 since it uses the table to find the tdb handle
 ********************************************************************/

static bool sync_eventlog_params( EVENTLOG_INFO *info )
{
	char *path = NULL;
	uint32 uiMaxSize;
	uint32 uiRetention;
	struct registry_key *key;
	struct registry_value *value;
	WERROR wresult;
	char *elogname = info->logname;
	TALLOC_CTX *ctx = talloc_stackframe();
	bool ret = false;

	DEBUG( 4, ( "sync_eventlog_params with %s\n", elogname ) );

	if ( !info->etdb ) {
		DEBUG( 4, ( "No open tdb! (%s)\n", info->logname ) );
		goto done;
	}
	/* set resonable defaults.  512Kb on size and 1 week on time */

	uiMaxSize = 0x80000;
	uiRetention = 604800;

	/* the general idea is to internally open the registry 
	   key and retrieve the values.  That way we can continue 
	   to use the same fetch/store api that we use in 
	   srv_reg_nt.c */

	path = talloc_asprintf(ctx, "%s/%s", KEY_EVENTLOG, elogname );
	if (!path) {
		goto done;
	}

	wresult = reg_open_path(ctx, path, REG_KEY_READ, get_root_nt_token(),
				&key);

	if ( !W_ERROR_IS_OK( wresult ) ) {
		DEBUG( 4,
		       ( "sync_eventlog_params: Failed to open key [%s] (%s)\n",
			 path, dos_errstr( wresult ) ) );
		goto done;
	}

	wresult = reg_queryvalue(key, key, "Retention", &value);
	if (!W_ERROR_IS_OK(wresult)) {
		DEBUG(4, ("Failed to query value \"Retention\": %s\n",
			  dos_errstr(wresult)));
		goto done;
	}
	uiRetention = value->v.dword;

	wresult = reg_queryvalue(key, key, "MaxSize", &value);
	if (!W_ERROR_IS_OK(wresult)) {
		DEBUG(4, ("Failed to query value \"MaxSize\": %s\n",
			  dos_errstr(wresult)));
		goto done;
	}
	uiMaxSize = value->v.dword;

	tdb_store_int32( ELOG_TDB_CTX(info->etdb), EVT_MAXSIZE, uiMaxSize );
	tdb_store_int32( ELOG_TDB_CTX(info->etdb), EVT_RETENTION, uiRetention );

	ret = true;

done:
	TALLOC_FREE(ctx);
	return ret;
}

/********************************************************************
 ********************************************************************/

static Eventlog_entry *read_package_entry( prs_struct * ps,
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
	memcpy( offset, entry->data_record.source_name,
		entry->data_record.source_name_len );
	offset += entry->data_record.source_name_len;
	memcpy( offset, entry->data_record.computer_name,
		entry->data_record.computer_name_len );
	offset += entry->data_record.computer_name_len;
	/* SID needs to be DWORD-aligned */
	offset += entry->data_record.sid_padding;
	entry->record.user_sid_offset =
		sizeof( Eventlog_record ) + ( offset - entry->data );
	memcpy( offset, entry->data_record.sid,
		entry->record.user_sid_length );
	offset += entry->record.user_sid_length;
	/* Now do the strings */
	entry->record.string_offset =
		sizeof( Eventlog_record ) + ( offset - entry->data );
	memcpy( offset, entry->data_record.strings,
		entry->data_record.strings_len );
	offset += entry->data_record.strings_len;
	/* Now do the data */
	entry->record.data_length = entry->data_record.user_data_len;
	entry->record.data_offset =
		sizeof( Eventlog_record ) + ( offset - entry->data );
	memcpy( offset, entry->data_record.user_data,
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

static bool add_record_to_resp( EVENTLOG_R_READ_EVENTLOG * r_u,
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
 _eventlog_OpenEventLogW
 ********************************************************************/

NTSTATUS _eventlog_OpenEventLogW(pipes_struct *p,
				 struct eventlog_OpenEventLogW *r)
{
	const char *servername = "";
	const char *logname = "";
	EVENTLOG_INFO *info;
	NTSTATUS result;

	if (r->in.servername->string) {
		servername = r->in.servername->string;
	}

	if (r->in.logname->string) {
		logname = r->in.logname->string;
	}
	
	DEBUG( 10,("_eventlog_open_eventlog: Server [%s], Log [%s]\n",
		servername, logname ));
		
	/* according to MSDN, if the logfile cannot be found, we should
	  default to the "Application" log */
	  
	if ( !NT_STATUS_IS_OK( result = elog_open( p, logname, r->out.handle )) )
		return result;

	if ( !(info = find_eventlog_info_by_hnd( p, r->out.handle )) ) {
		DEBUG(0,("_eventlog_open_eventlog: eventlog (%s) opened but unable to find handle!\n",
			logname ));
		elog_close( p, r->out.handle );
		return NT_STATUS_INVALID_HANDLE;
	}

	DEBUG(10,("_eventlog_open_eventlog: Size [%d]\n", elog_size( info )));

	sync_eventlog_params( info );
	prune_eventlog( ELOG_TDB_CTX(info->etdb) );

	return NT_STATUS_OK;
}

/********************************************************************
 _eventlog_ClearEventLogW
 This call still needs some work
 ********************************************************************/
/** The windows client seems to be doing something funny with the file name
   A call like
      ClearEventLog(handle, "backup_file")
   on the client side will result in the backup file name looking like this on the
   server side:
      \??\${CWD of client}\backup_file
   If an absolute path gets specified, such as
      ClearEventLog(handle, "C:\\temp\\backup_file")
   then it is still mangled by the client into this:
      \??\C:\temp\backup_file
   when it is on the wire.
   I'm not sure where the \?? is coming from, or why the ${CWD} of the client process
   would be added in given that the backup file gets written on the server side. */

NTSTATUS _eventlog_ClearEventLogW(pipes_struct *p,
				  struct eventlog_ClearEventLogW *r)
{
	EVENTLOG_INFO *info = find_eventlog_info_by_hnd( p, r->in.handle );
	const char *backup_file_name = NULL;

	if ( !info )
		return NT_STATUS_INVALID_HANDLE;

	if (r->in.backupfile && r->in.backupfile->string) {

		backup_file_name = r->in.backupfile->string;

		DEBUG(8,( "_eventlog_clear_eventlog: Using [%s] as the backup "
			"file name for log [%s].",
			 backup_file_name, info->logname ) );
	}

	/* check for WRITE access to the file */

	if ( !(info->access_granted&SA_RIGHT_FILE_WRITE_DATA) )
		return NT_STATUS_ACCESS_DENIED;

	/* Force a close and reopen */

	elog_close_tdb( info->etdb, True );
	become_root();
	info->etdb = elog_open_tdb( info->logname, True );
	unbecome_root();

	if ( !info->etdb )
		return NT_STATUS_ACCESS_DENIED;

	return NT_STATUS_OK;
}

/********************************************************************
 ********************************************************************/

NTSTATUS _eventlog_CloseEventLog( pipes_struct * p, struct eventlog_CloseEventLog *r )
{
	return elog_close( p, r->in.handle );
}

/********************************************************************
 ********************************************************************/

NTSTATUS _eventlog_read_eventlog( pipes_struct * p,
				EVENTLOG_Q_READ_EVENTLOG * q_u,
				EVENTLOG_R_READ_EVENTLOG * r_u )
{
	EVENTLOG_INFO *info = find_eventlog_info_by_hnd( p, &q_u->handle );
	Eventlog_entry *entry = NULL, *ee_new = NULL;
	uint32 num_records_read = 0;
	prs_struct *ps;
	int bytes_left, record_number;
	uint32 elog_read_type, elog_read_dir;

	if (info == NULL) {
		return NT_STATUS_INVALID_HANDLE;
	}

	info->flags = q_u->flags;
	ps = &p->out_data.rdata;

	bytes_left = q_u->max_read_size;

	if ( !info->etdb )
		return NT_STATUS_ACCESS_DENIED;

	/* check for valid flags.  Can't use the sequential and seek flags together */

	elog_read_type = q_u->flags & (EVENTLOG_SEQUENTIAL_READ|EVENTLOG_SEEK_READ);
	elog_read_dir = q_u->flags & (EVENTLOG_FORWARDS_READ|EVENTLOG_BACKWARDS_READ);

	if ( elog_read_type == (EVENTLOG_SEQUENTIAL_READ|EVENTLOG_SEEK_READ) 
		||  elog_read_dir == (EVENTLOG_FORWARDS_READ|EVENTLOG_BACKWARDS_READ) )
	{
		DEBUG(3,("_eventlog_read_eventlog: Invalid flags [0x%x] for ReadEventLog\n", q_u->flags));
		return NT_STATUS_INVALID_PARAMETER;
	}

	/* a sequential read should ignore the offset */

	if ( elog_read_type & EVENTLOG_SEQUENTIAL_READ )
		record_number = info->current_record;
	else
		record_number = q_u->offset;

	while ( bytes_left > 0 ) {

		/* assume that when the record fetch fails, that we are done */

		entry = get_eventlog_record (ps, ELOG_TDB_CTX(info->etdb), record_number);
		if (!entry) {
			break;
		}

		DEBUG( 8, ( "Retrieved record %d\n", record_number ) );

		/* Now see if there is enough room to add */

		if ( !(ee_new = read_package_entry( ps, entry )) )
			return NT_STATUS_NO_MEMORY;

		if ( r_u->num_bytes_in_resp + ee_new->record.length > q_u->max_read_size ) {
			r_u->bytes_in_next_record = ee_new->record.length;

			/* response would be too big to fit in client-size buffer */

			bytes_left = 0;
			break;
		}

		add_record_to_resp( r_u, ee_new );
		bytes_left -= ee_new->record.length;
		TALLOC_FREE(entry);
		num_records_read = r_u->num_records - num_records_read;

		DEBUG( 10, ( "_eventlog_read_eventlog: read [%d] records for a total "
			"of [%d] records using [%d] bytes out of a max of [%d].\n",
			 num_records_read, r_u->num_records,
			 r_u->num_bytes_in_resp,
			 q_u->max_read_size ) );

		if ( info->flags & EVENTLOG_FORWARDS_READ )
			record_number++;
		else
			record_number--;

		/* update the eventlog record pointer */

		info->current_record = record_number;
	}

	/* crazy by WinXP uses NT_STATUS_BUFFER_TOO_SMALL to
	   say when there are no more records */

	return (num_records_read ? NT_STATUS_OK : NT_STATUS_BUFFER_TOO_SMALL);
}

/********************************************************************
 _eventlog_GetOldestRecord
 ********************************************************************/

NTSTATUS _eventlog_GetOldestRecord(pipes_struct *p,
				   struct eventlog_GetOldestRecord *r)
{
	EVENTLOG_INFO *info = find_eventlog_info_by_hnd( p, r->in.handle );

	if (info == NULL) {
		return NT_STATUS_INVALID_HANDLE;
	}

	if ( !( get_oldest_entry_hook( info ) ) )
		return NT_STATUS_ACCESS_DENIED;

	*r->out.oldest_entry = info->oldest_entry;

	return NT_STATUS_OK;
}

/********************************************************************
_eventlog_GetNumRecords
 ********************************************************************/

NTSTATUS _eventlog_GetNumRecords(pipes_struct *p,
				 struct eventlog_GetNumRecords *r)
{
	EVENTLOG_INFO *info = find_eventlog_info_by_hnd( p, r->in.handle );

	if (info == NULL) {
		return NT_STATUS_INVALID_HANDLE;
	}

	if ( !( get_num_records_hook( info ) ) )
		return NT_STATUS_ACCESS_DENIED;

	*r->out.number = info->num_records;

	return NT_STATUS_OK;
}

NTSTATUS _eventlog_BackupEventLogW(pipes_struct *p, struct eventlog_BackupEventLogW *r)
{
	p->rng_fault_state = True;
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS _eventlog_DeregisterEventSource(pipes_struct *p, struct eventlog_DeregisterEventSource *r)
{
	p->rng_fault_state = True;
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS _eventlog_ChangeNotify(pipes_struct *p, struct eventlog_ChangeNotify *r)
{
	p->rng_fault_state = True;
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS _eventlog_RegisterEventSourceW(pipes_struct *p, struct eventlog_RegisterEventSourceW *r)
{
	p->rng_fault_state = True;
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS _eventlog_OpenBackupEventLogW(pipes_struct *p, struct eventlog_OpenBackupEventLogW *r)
{
	p->rng_fault_state = True;
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS _eventlog_ReadEventLogW(pipes_struct *p, struct eventlog_ReadEventLogW *r)
{
	p->rng_fault_state = True;
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS _eventlog_ReportEventW(pipes_struct *p, struct eventlog_ReportEventW *r)
{
	p->rng_fault_state = True;
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS _eventlog_ClearEventLogA(pipes_struct *p, struct eventlog_ClearEventLogA *r)
{
	p->rng_fault_state = True;
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS _eventlog_BackupEventLogA(pipes_struct *p, struct eventlog_BackupEventLogA *r)
{
	p->rng_fault_state = True;
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS _eventlog_OpenEventLogA(pipes_struct *p, struct eventlog_OpenEventLogA *r)
{
	p->rng_fault_state = True;
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS _eventlog_RegisterEventSourceA(pipes_struct *p, struct eventlog_RegisterEventSourceA *r)
{
	p->rng_fault_state = True;
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS _eventlog_OpenBackupEventLogA(pipes_struct *p, struct eventlog_OpenBackupEventLogA *r)
{
	p->rng_fault_state = True;
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS _eventlog_ReadEventLogA(pipes_struct *p, struct eventlog_ReadEventLogA *r)
{
	p->rng_fault_state = True;
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS _eventlog_ReportEventA(pipes_struct *p, struct eventlog_ReportEventA *r)
{
	p->rng_fault_state = True;
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS _eventlog_RegisterClusterSvc(pipes_struct *p, struct eventlog_RegisterClusterSvc *r)
{
	p->rng_fault_state = True;
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS _eventlog_DeregisterClusterSvc(pipes_struct *p, struct eventlog_DeregisterClusterSvc *r)
{
	p->rng_fault_state = True;
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS _eventlog_WriteClusterEvents(pipes_struct *p, struct eventlog_WriteClusterEvents *r)
{
	p->rng_fault_state = True;
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS _eventlog_GetLogIntormation(pipes_struct *p, struct eventlog_GetLogIntormation *r)
{
	p->rng_fault_state = True;
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS _eventlog_FlushEventLog(pipes_struct *p, struct eventlog_FlushEventLog *r)
{
	p->rng_fault_state = True;
	return NT_STATUS_NOT_IMPLEMENTED;
}

