/* 
 *  Unix SMB/CIFS implementation.
 *  RPC Pipe client / server routines
 *  Copyright (C) Marcin Krzysztof Porwit    2005,
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

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_RPC_SRV

typedef struct {
	char *logname;
	char *servername;
	uint32 num_records;
	uint32 oldest_entry;
	uint32 flags;
} EventlogInfo;

  
/********************************************************************
 Inform the external eventlog machinery of default values (on startup 
 probably)
********************************************************************/

void eventlog_refresh_external_parameters( NT_USER_TOKEN *token )
{
	const char **elogs = lp_eventlog_list();
	int i;

	if ( !elogs )
		return ;

	if ( !*lp_eventlog_control_cmd() )
		return;

	for ( i=0; elogs[i]; i++ ) {
	
		DEBUG(10,("eventlog_refresh_external_parameters: Refreshing =>[%s]\n", 
			elogs[i]));	
		
		if ( !control_eventlog_hook( token, elogs[i] ) ) {
			DEBUG(0,("eventlog_refresh_external_parameters: failed to refresh [%s]\n",
				elogs[i]));
		}
	}  
    
	return;
}

/********************************************************************
********************************************************************/

static void free_eventlog_info(void *ptr)
{
	TALLOC_FREE( ptr );
}

/********************************************************************
********************************************************************/

static EventlogInfo *find_eventlog_info_by_hnd(pipes_struct *p, POLICY_HND *handle)
{
	EventlogInfo *info;
    
	if ( !find_policy_by_hnd(p,handle,(void **)&info) ) {
		DEBUG(2,("find_eventlog_info_by_hnd: eventlog not found.\n"));
		return NULL;
	}

	return info;
}

/********************************************************************
 Callout to control the specified event log - passing out only 
 the MaxSize and Retention values, along with eventlog name
 uses smbrun...
      INPUT: <control_cmd> <log name> <retention> <maxsize>
      OUTPUT: nothing
********************************************************************/

BOOL control_eventlog_hook(NT_USER_TOKEN *token, const char *elogname )
{
	char *cmd = lp_eventlog_control_cmd();
	pstring command;
	int ret;
	int fd = -1;
	uint32 uiMaxSize, uiRetention;
	pstring path;
	REGISTRY_KEY *keyinfo;
	REGISTRY_VALUE *val;
	REGVAL_CTR *values;
	WERROR wresult;

	if ( !cmd || !*cmd ) {
		DEBUG(0, ("control_eventlog_hook: No \"eventlog control command\" defined in smb.conf!\n"));
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
	wresult = regkey_open_internal( &keyinfo, path, token, REG_KEY_READ );
	
	if ( !W_ERROR_IS_OK( wresult ) ) {
		DEBUG(4,("control_eventlog_hook: Failed to open key [%s] (%s)\n",
			path, dos_errstr(wresult) ));
		return False;
	}
	
	if ( !(values = TALLOC_ZERO_P( keyinfo, REGVAL_CTR )) ) {
		TALLOC_FREE( keyinfo );
		DEBUG(0,("control_eventlog_hook: talloc() failed!\n"));
		
		return False;
	}
	fetch_reg_values( keyinfo, values );
	
	if ( (val = regval_ctr_getvalue( values, "Retention" )) != NULL )
		uiRetention = IVAL( regval_data_p(val), 0 );

	if ( (val = regval_ctr_getvalue( values, "MaxSize" )) != NULL )
		uiMaxSize = IVAL( regval_data_p(val), 0 );
		
	TALLOC_FREE( keyinfo );
	
	/* now run the command */

	pstr_sprintf(command, "%s \"%s\" %u %u", cmd, elogname, uiRetention, uiMaxSize );

	DEBUG(10, ("control_eventlog_hook: Running [%s]\n", command));
	ret = smbrun(command, &fd);
	DEBUGADD(10, ("returned [%d]\n", ret));

	if ( ret != 0 ) {
		DEBUG(10,("control_eventlog_hook: Command returned  [%d]\n", ret));
		if (fd != -1 )
			close(fd);
		return False;
	}

	close(fd);
	return True;
}


/********************************************************************
********************************************************************/

/**
 * Callout to open the specified event log
 * 
 *   smbrun calling convention --
 *     INPUT: <open_cmd> <log name> <policy handle>
 *     OUTPUT: the string "SUCCESS" if the command succeeded
 *             no such string if there was a failure.
 */
static BOOL open_eventlog_hook( EventlogInfo *info )
{
	char *cmd = lp_eventlog_open_cmd();
	char **qlines;
	pstring command;
	int numlines = 0;
	int ret;
	int fd = -1;

	if ( !cmd || !*cmd ) {
		DEBUG(0, ("Must define an \"eventlog open command\" entry in the config.\n"));
		return False;
	}

	pstr_sprintf(command, "%s \"%s\"", cmd, info->logname );

	DEBUG(10, ("Running [%s]\n", command));
	ret = smbrun(command, &fd);
	DEBUGADD(10, ("returned [%d]\n", ret));

	if(ret != 0) {
		if(fd != -1) {
			close(fd);
		}
		return False;
	}

	qlines = fd_lines_load(fd, &numlines);
	DEBUGADD(10, ("Lines returned = [%d]\n", numlines));
	close(fd);

	if(numlines) {
		DEBUGADD(10, ("Line[0] = [%s]\n", qlines[0]));
		if(0 == strncmp(qlines[0], "SUCCESS", strlen("SUCCESS"))) {
			DEBUGADD(10, ("Able to open [%s].\n", info->logname));
			file_lines_free(qlines);
			return True;
		}
	}

	file_lines_free(qlines);

	return False;
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

static BOOL get_num_records_hook(EventlogInfo *info)
{
	char *cmd = lp_eventlog_num_records_cmd();
	char **qlines;
	pstring command;
	int numlines = 0;
	int ret;
	int fd = -1;

	if ( !cmd || !*cmd ) {
		DEBUG(0, ("Must define an \"eventlog num records command\" entry in the config.\n"));
		return False;
	}

	pstr_sprintf( command, "%s \"%s\"", cmd, info->logname );

	DEBUG(10, ("Running [%s]\n", command));
	ret = smbrun(command, &fd);
	DEBUGADD(10, ("returned [%d]\n", ret));

	if(ret != 0) {
		if(fd != -1) {
			close(fd);
		}
		return False;
	}

	qlines = fd_lines_load(fd, &numlines);
	DEBUGADD(10, ("Lines returned = [%d]\n", numlines));
	close(fd);

	if(numlines) {
		DEBUGADD(10, ("Line[0] = [%s]\n", qlines[0]));
		sscanf(qlines[0], "%d", &(info->num_records));
		file_lines_free(qlines);
		return True;
	}

	file_lines_free(qlines);
	return False;
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

static BOOL get_oldest_entry_hook(EventlogInfo *info)
{
	char *cmd = lp_eventlog_oldest_record_cmd();
	char **qlines;
	pstring command;
	int numlines = 0;
	int ret;
	int fd = -1;

	if ( !cmd || !*cmd ) {
		DEBUG(0, ("Must define an \"eventlog oldest record command\" entry in the config.\n"));
		return False;
	}

	pstr_sprintf( command, "%s \"%s\"", cmd, info->logname );

	DEBUG(10, ("Running [%s]\n", command));
	ret = smbrun(command, &fd);
	DEBUGADD(10, ("returned [%d]\n", ret));

	if(ret != 0) {
		if(fd != -1) {
			close(fd);
		}
		return False;
	}

	qlines = fd_lines_load(fd, &numlines);
	DEBUGADD(10, ("Lines returned = [%d]\n", numlines));
	close(fd);

	if(numlines) {
		DEBUGADD(10, ("Line[0] = [%s]\n", qlines[0]));
		sscanf(qlines[0], "%d", &(info->oldest_entry));
		file_lines_free(qlines);
		return True;
	}

	file_lines_free(qlines);
	return False;
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

static BOOL close_eventlog_hook(EventlogInfo *info)
{
	char *cmd = lp_eventlog_close_cmd();
	char **qlines;
	pstring command;
	int numlines = 0;
	int ret;
	int fd = -1;

	if ( !cmd || !*cmd ) {
		DEBUG(0, ("Must define an \"eventlog close command\" entry in the config.\n"));
		return False;
	}

	pstr_sprintf( command, "%s \"%s\"", cmd, info->logname );

	DEBUG(10, ("Running [%s]\n", command));
	ret = smbrun(command, &fd);
	DEBUGADD(10, ("returned [%d]\n", ret));

	if(ret != 0) {
		if(fd != -1) {
			close(fd);
		}
		return False;
	}

	qlines = fd_lines_load(fd, &numlines);
	DEBUGADD(10, ("Lines returned = [%d]\n", numlines));
	close(fd);

	if(numlines) {
		DEBUGADD(10, ("Line[0] = [%s]\n", qlines[0]));
		if(0 == strncmp(qlines[0], "SUCCESS", 7)) {
			DEBUGADD(10, ("Able to close [%s].\n", info->logname));
			file_lines_free(qlines);
			return True;
		}
	}

	file_lines_free(qlines);
	return False;
}

/********************************************************************
********************************************************************/

static BOOL parse_logentry(char *line, Eventlog_entry *entry, BOOL *eor)
{
	char *start = NULL, *stop = NULL;
	pstring temp;
	int temp_len = 0, i;
 
	start = line;

	/* empty line signyfiying record delimeter, or we're at the end of the buffer */
	if(start == NULL || strlen(start) == 0) {
		DEBUG(6, ("parse_logentry: found end-of-record indicator.\n"));
		*eor = True;
		return True;
	}
	if(!(stop = strchr(line, ':'))) {
		return False;
	}
    
	DEBUG(6, ("parse_logentry: trying to parse [%s].\n", line));

	if(0 == strncmp(start, "LEN", stop - start)) {
		/* This will get recomputed later anyway -- probably not necessary */
		entry->record.length = atoi(stop + 1);
	} else if(0 == strncmp(start, "RS1", stop - start)) {
		/* For now all these reserved entries seem to have the same value,
		   which can be hardcoded to int(1699505740) for now */
		entry->record.reserved1 = atoi(stop + 1);
	} else if(0 == strncmp(start, "RCN", stop - start)) {
		entry->record.record_number = atoi(stop + 1);
	} else if(0 == strncmp(start, "TMG", stop - start)) {
		entry->record.time_generated = atoi(stop + 1);
	} else if(0 == strncmp(start, "TMW", stop - start)) {
		entry->record.time_written = atoi(stop + 1);
	} else if(0 == strncmp(start, "EID", stop - start)) {
		entry->record.event_id = atoi(stop + 1);
	} else if(0 == strncmp(start, "ETP", stop - start)) {
		if(strstr(start, "ERROR")) {
			entry->record.event_type = EVENTLOG_ERROR_TYPE;
		} else if(strstr(start, "WARNING")) {
			entry->record.event_type = EVENTLOG_WARNING_TYPE;
		} else if(strstr(start, "INFO")) {
			entry->record.event_type = EVENTLOG_INFORMATION_TYPE;
		} else if(strstr(start, "AUDIT_SUCCESS")) {
			entry->record.event_type = EVENTLOG_AUDIT_SUCCESS;
		} else if(strstr(start, "AUDIT_FAILURE")) {
			entry->record.event_type = EVENTLOG_AUDIT_FAILURE;
		} else if(strstr(start, "SUCCESS")) {
			entry->record.event_type = EVENTLOG_SUCCESS;
		} else {
			/* some other eventlog type -- currently not defined in MSDN docs, so error out */
			return False;
		}
	}
/*
  else if(0 == strncmp(start, "NST", stop - start))
  {
  entry->record.num_strings = atoi(stop + 1);
  }
*/
	else if(0 == strncmp(start, "ECT", stop - start)) {
		entry->record.event_category = atoi(stop + 1);
	} else if(0 == strncmp(start, "RS2", stop - start)) {
		entry->record.reserved2 = atoi(stop + 1);
	} else if(0 == strncmp(start, "CRN", stop - start)) {
		entry->record.closing_record_number = atoi(stop + 1);
	} else if(0 == strncmp(start, "USL", stop - start)) {
		entry->record.user_sid_length = atoi(stop + 1);
	} else if(0 == strncmp(start, "SRC", stop - start)) {
		memset(temp, 0, sizeof(temp));
		stop++;
		while(isspace(stop[0])) {
			stop++;
		}
		temp_len = strlen(stop);
		strncpy(temp, stop, temp_len);
		rpcstr_push((void *)(entry->data_record.source_name), temp, 
			    sizeof(entry->data_record.source_name), STR_TERMINATE);
		entry->data_record.source_name_len = (strlen_w(entry->data_record.source_name)* 2) + 2;
	} else if(0 == strncmp(start, "SRN", stop - start)) {
		memset(temp, 0, sizeof(temp));
		stop++;
		while(isspace(stop[0])) {
			stop++; 
		}
		temp_len = strlen(stop);
		strncpy(temp, stop, temp_len);
		rpcstr_push((void *)(entry->data_record.computer_name), temp,
			    sizeof(entry->data_record.computer_name), STR_TERMINATE);
		entry->data_record.computer_name_len = (strlen_w(entry->data_record.computer_name)* 2) + 2;
	} else if(0 == strncmp(start, "SID", stop - start)) {
		memset(temp, 0, sizeof(temp));
		stop++;
		while(isspace(stop[0])) {
			stop++;
		}
		temp_len = strlen(stop);
		strncpy(temp, stop, temp_len);
		rpcstr_push((void *)(entry->data_record.sid), temp,
			    sizeof(entry->data_record.sid), STR_TERMINATE);
		entry->record.user_sid_length = (strlen_w(entry->data_record.sid) * 2) + 2;
	} else if(0 == strncmp(start, "STR", stop - start)) {
		/* skip past initial ":" */
		stop++;
		/* now skip any other leading whitespace */
		while(isspace(stop[0])) {
			stop++;
		}
		temp_len = strlen(stop);
		memset(temp, 0, sizeof(temp));
		strncpy(temp, stop, temp_len);
		rpcstr_push((void *)(entry->data_record.strings + entry->data_record.strings_len),
			    temp,
			    sizeof(entry->data_record.strings) - entry->data_record.strings_len, 
			    STR_TERMINATE);
		entry->data_record.strings_len += temp_len + 1;
		fprintf(stderr, "Dumping strings:\n");
		for(i = 0; i < entry->data_record.strings_len; i++) {
			fputc((char)entry->data_record.strings[i], stderr);
		}
		fprintf(stderr, "\nDone\n");
		entry->record.num_strings++;
	} else if(0 == strncmp(start, "DAT", stop - start)) {
		/* Now that we're done processing the STR data, adjust the length to account for
		   unicode, then proceed with the DAT data. */
		entry->data_record.strings_len *= 2;
		/* skip past initial ":" */
		stop++;
		/* now skip any other leading whitespace */
		while(isspace(stop[0])) {
			stop++;
		}
		entry->data_record.user_data_len = strlen(stop);
		memset(entry->data_record.user_data, 0, sizeof(entry->data_record.user_data));
		if(entry->data_record.user_data_len > 0) {
			/* copy no more than the first 1024 bytes */
			if(entry->data_record.user_data_len > sizeof(entry->data_record.user_data))
				entry->data_record.user_data_len = sizeof(entry->data_record.user_data);
			memcpy(entry->data_record.user_data, stop, entry->data_record.user_data_len);
		}
	} else {
		/* some other eventlog entry -- not implemented, so dropping on the floor */
		DEBUG(10, ("Unknown entry [%s]. Ignoring.\n", line));
		/* For now return true so that we can keep on parsing this mess. Eventually
		   we will return False here. */
		return True;
	}
	return True;
}

/********************************************************************
********************************************************************/

/**
 * Callout to read entries from the specified event log
 *
 *   smbrun calling convention --
 *     INPUT: <read_cmd> <log name> <direction> <starting record> <buffer size> <policy handle>
 *            where direction is either "forward" or "backward", the starting record is somewhere
 *            between the oldest_record and oldest_record+num_records, and the buffer size is the
 *            maximum size of the buffer that the client can accomodate.
 *     OUTPUT: A buffer containing a set of entries, one to a line, of the format:
 *             Multiple log entries can be contained in the buffer, delimited by an empty line
 *               line type:line data
 *             These are the allowed line types:
 *               RS1:(uint32) - reserved. All M$ entries seem to have int(1699505740) for now
 *               RCN:(uint32) - record number of the record, however it may be calculated by the script
 *               TMG:(uint32) - time generated, seconds since January 1, 1970, 0000 UTC
 *               TMW:(uint32) - time written, seconds since January 1, 1970, 0000 UTC
 *               EID:(uint32) - eventlog source defined event identifier. If there's a stringfile for the event, it is an index into that
 *               ETP:(uint16) - eventlog type - one of ERROR, WARNING, INFO, AUDIT_SUCCESS, AUDIT_FAILURE
 *               ECT:(uint16) - event category - depends on the eventlog generator... 
 *               RS2:(uint16) - reserved, make it 0000
 *               CRN:(uint32) - reserved, make it 00000000 for now
 *               USL:(uint32) - user SID length. No sid? Make this 0. Must match SID below
 *               SRC:[(uint8)] - Name of the source, for example ccPwdSvc, in hex bytes. Can not be multiline.
 *               SRN:[(uint8)] - Name of the computer on which this is generated, the short hostname usually.
 *               SID:[(uint8)] - User sid if one exists. Must be present even if there is no SID.
 *               STR:[(uint8)] - String data. One string per line. Multiple strings can be specified using consecutive "STR" lines,
 *                               up to a total aggregate string length of 1024 characters.
 *               DAT:[(uint8)] - The user-defined data portion of the event log. Can not be multiple lines.
 *               <empty line>  - end-of-record indicator 
 */

static BOOL read_eventlog_hook(EventlogInfo *info, Eventlog_entry *entry, 
					 const char *direction, int starting_record, 
					 int buffer_size, BOOL *eof,
					 char ***buffer, int *numlines)
{
	char *cmd = lp_eventlog_read_cmd();
	pstring command;
	int ret;
	int fd = -1;

	if ( !info )
		return False;

	if ( !cmd || !*cmd ) {
		DEBUG(0, ("Must define an \"eventlog read command\" entry in the config.\n"));
		return False;
	}

	pstr_sprintf( command, "%s \"%s\" %s %d %d",
		 cmd, info->logname, direction, starting_record, buffer_size );

	*numlines = 0;

	DEBUG(10, ("Running [%s]\n", command));
	ret = smbrun(command, &fd);
	DEBUGADD(10, ("returned [%d]\n", ret));

	if(ret != 0) {
		if(fd != -1) {
			close(fd);
		}
		return False;
	}

	*buffer = fd_lines_load(fd, numlines);
	DEBUGADD(10, ("Lines returned = [%d]\n", *numlines));
	close(fd);
    
	if(*numlines) {
		/*
		  for(i = 0; i < numlines; i++)
		  {
		  DEBUGADD(10, ("Line[%d] = %s\n", i, qlines[i]));
		  parse_logentry(qlines[i], entry);
		  }
		  file_lines_free(qlines);
		*/
		*eof = False;
		return True;
	}
	*eof = True;

/*    file_lines_free(qlines);*/
	return False;
}

/********************************************************************
********************************************************************/

static Eventlog_entry *read_package_entry(prs_struct *ps,
						    EVENTLOG_Q_READ_EVENTLOG *q_u,
						    EVENTLOG_R_READ_EVENTLOG *r_u,
						    Eventlog_entry *entry)
{
	uint8 *offset;
	Eventlog_entry *ee_new = NULL;

	ee_new = PRS_ALLOC_MEM(ps, Eventlog_entry, 1);
	if(ee_new == NULL) {
		return NULL;
	}

	entry->data_record.sid_padding = ((4 - ((entry->data_record.source_name_len 
						 + entry->data_record.computer_name_len) % 4)) %4);
	entry->data_record.data_padding = (4 - ((entry->data_record.strings_len 
						 + entry->data_record.user_data_len) % 4)) % 4;
	entry->record.length = sizeof(Eventlog_record);
	entry->record.length += entry->data_record.source_name_len;
	entry->record.length += entry->data_record.computer_name_len;
	if(entry->record.user_sid_length == 0) {
		/* Should not pad to a DWORD boundary for writing out the sid if there is
		   no SID, so just propagate the padding to pad the data */
		entry->data_record.data_padding += entry->data_record.sid_padding;
		entry->data_record.sid_padding = 0;
	}
	DEBUG(10, ("sid_padding is [%d].\n", entry->data_record.sid_padding));
	DEBUG(10, ("data_padding is [%d].\n", entry->data_record.data_padding));

	entry->record.length += entry->data_record.sid_padding;
	entry->record.length += entry->record.user_sid_length;
	entry->record.length += entry->data_record.strings_len;
	entry->record.length += entry->data_record.user_data_len;
	entry->record.length += entry->data_record.data_padding;
	/* need another copy of length at the end of the data */
	entry->record.length += sizeof(entry->record.length);
	DEBUG(10, ("entry->record.length is [%d].\n", entry->record.length));
	entry->data = PRS_ALLOC_MEM(ps, uint8, entry->record.length - sizeof(Eventlog_record) - sizeof(entry->record.length));
	if(entry->data == NULL) {
		return NULL;
	}
	offset = entry->data;
	memcpy(offset, &(entry->data_record.source_name), entry->data_record.source_name_len);
	offset += entry->data_record.source_name_len;
	memcpy(offset, &(entry->data_record.computer_name), entry->data_record.computer_name_len);
	offset += entry->data_record.computer_name_len;
	/* SID needs to be DWORD-aligned */
	offset += entry->data_record.sid_padding;
	entry->record.user_sid_offset = sizeof(Eventlog_record) + (offset - entry->data);
	memcpy(offset, &(entry->data_record.sid), entry->record.user_sid_length);
	offset += entry->record.user_sid_length;
	/* Now do the strings */
	entry->record.string_offset = sizeof(Eventlog_record) + (offset - entry->data);
	memcpy(offset, &(entry->data_record.strings), entry->data_record.strings_len);
	offset += entry->data_record.strings_len;
	/* Now do the data */
	entry->record.data_length = entry->data_record.user_data_len;
	entry->record.data_offset = sizeof(Eventlog_record) + (offset - entry->data);
	memcpy(offset, &(entry->data_record.user_data), entry->data_record.user_data_len);
	offset += entry->data_record.user_data_len;

	memcpy(&(ee_new->record), &entry->record, sizeof(Eventlog_record));
	memcpy(&(ee_new->data_record), &entry->data_record, sizeof(Eventlog_data_record));
	ee_new->data = entry->data;

	return ee_new;
}

/********************************************************************
********************************************************************/

static BOOL add_record_to_resp(EVENTLOG_R_READ_EVENTLOG *r_u, Eventlog_entry *ee_new)
{
	Eventlog_entry *insert_point;

	insert_point=r_u->entry;

	if (NULL == insert_point) {
		r_u->entry = ee_new;
		ee_new->next = NULL;
	} else {
		while ((NULL != insert_point->next)) {
			insert_point=insert_point->next;
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

static BOOL clear_eventlog_hook(EventlogInfo *info, pstring backup_file_name)
{
	char *cmd = lp_eventlog_clear_cmd();
	char **qlines;
	pstring command;
	int numlines = 0;
	int ret;
	int fd = -1;

	if ( !cmd || !*cmd ) {
		DEBUG(0, ("Must define an \"eventlog clear command\" entry in the config.\n"));
		return False;
	}

	if ( strlen(backup_file_name) ) 
		pstr_sprintf( command, "%s \"%s\" \"%s\"", cmd, info->logname, backup_file_name );
	else 
		pstr_sprintf( command, "%s \"%s\"", cmd, info->logname );

	DEBUG(10, ("Running [%s]\n", command));
	ret = smbrun(command, &fd);
	DEBUGADD(10, ("returned [%d]\n", ret));

	if(ret != 0) {
		if(fd != -1) {
			close(fd);
		}
		return False;
	}

	qlines = fd_lines_load(fd, &numlines);
	DEBUGADD(10, ("Lines returned = [%d]\n", numlines));
	close(fd);

	if(numlines) {
		DEBUGADD(10, ("Line[0] = [%s]\n", qlines[0]));
		if(0 == strncmp(qlines[0], "SUCCESS", strlen("SUCCESS"))) {
			DEBUGADD(10, ("Able to clear [%s].\n", info->logname));
			file_lines_free(qlines);
			return True;
		}
	}

	file_lines_free(qlines);
	return False;
}

/*******************************************************************
*******************************************************************/

WERROR _eventlog_open_eventlog(pipes_struct *p, EVENTLOG_Q_OPEN_EVENTLOG *q_u, EVENTLOG_R_OPEN_EVENTLOG *r_u)
{
	EventlogInfo *info = NULL;
	fstring str;
    
	if ( !(info = TALLOC_ZERO_P(NULL, EventlogInfo)) ) 
		return WERR_NOMEM;

	fstrcpy( str, global_myname() );
	if ( q_u->servername.string ) {
		rpcstr_pull( str, q_u->servername.string->buffer, 
			sizeof(str), q_u->servername.string->uni_str_len*2, 0 );
	} 
	info->servername = talloc_strdup( info, str );

	fstrcpy( str, "Application" );
	if ( q_u->logname.string ) {
		rpcstr_pull( str, q_u->logname.string->buffer, 
			sizeof(str), q_u->logname.string->uni_str_len*2, 0 );
	} 
	info->logname = talloc_strdup( info, str );

	DEBUG(10, ("_eventlog_open_eventlog: Using [%s] as the server name.\n", info->servername));
	DEBUG(10, ("_eventlog_open_eventlog: Using [%s] as the source log file.\n", info->logname));

	if ( !create_policy_hnd(p, &r_u->handle, free_eventlog_info, (void *)info) ) {
		free_eventlog_info(info);
		return WERR_NOMEM;
	}
	
	if ( !(open_eventlog_hook(info)) ) {
		close_policy_hnd(p, &r_u->handle);
		return WERR_BADFILE;
	}
	
	return WERR_OK;
}

/********************************************************************
********************************************************************/

WERROR _eventlog_clear_eventlog(pipes_struct *p, EVENTLOG_Q_CLEAR_EVENTLOG *q_u, EVENTLOG_R_CLEAR_EVENTLOG *r_u)
{
	EventlogInfo *info = find_eventlog_info_by_hnd(p, &q_u->handle);
	pstring backup_file_name;

	pstrcpy( backup_file_name, "" );

	if ( q_u->backupfile.string ) 
		unistr2_to_ascii(backup_file_name, q_u->backupfile.string, sizeof(backup_file_name));

	DEBUG(10, ("_eventlog_clear_eventlog: Using [%s] as the backup file name for log [%s].",
		   backup_file_name, info->logname));

	if ( !(clear_eventlog_hook(info, backup_file_name)) )
		return WERR_BADFILE;

	return WERR_OK;
}

/********************************************************************
********************************************************************/

WERROR _eventlog_close_eventlog(pipes_struct *p, EVENTLOG_Q_CLOSE_EVENTLOG *q_u, EVENTLOG_R_CLOSE_EVENTLOG *r_u)
{
	EventlogInfo *info = find_eventlog_info_by_hnd(p,&q_u->handle);

	if ( !(close_eventlog_hook(info)) )
		return WERR_BADFILE;

	if ( !(close_policy_hnd(p, &q_u->handle)) ) {
		return WERR_BADFID;
	}

	return WERR_OK;
}

/********************************************************************
********************************************************************/
   
WERROR _eventlog_read_eventlog(pipes_struct *p, EVENTLOG_Q_READ_EVENTLOG *q_u, EVENTLOG_R_READ_EVENTLOG *r_u)
{
	EventlogInfo *info = find_eventlog_info_by_hnd(p, &q_u->handle);
	Eventlog_entry entry, *ee_new;
	BOOL eof = False, eor = False;
	const char *direction = "";
	uint32 num_records_read = 0;
	prs_struct *ps;
	int numlines, i;
	char **buffer;

	info->flags = q_u->flags;
	ps = &p->out_data.rdata;

	if ( info->flags & EVENTLOG_FORWARDS_READ ) 
		direction = "forward";
	else if ( info->flags & EVENTLOG_BACKWARDS_READ )
		direction = "backward";

	if ( !(read_eventlog_hook(info, &entry, direction, q_u->offset, q_u->max_read_size, &eof, &buffer, &numlines)) ) {
		if(eof == False) {
			return WERR_NOMEM;
		}
	}

	if(numlines > 0) {
		ZERO_STRUCT(entry);
		for(i = 0; i < numlines; i++) {
			num_records_read = r_u->num_records;
			DEBUGADD(10, ("Line[%d] = [%s]\n", i, buffer[i]));
			parse_logentry(buffer[i], &entry, &eor);
			if(eor == True) {
				/* package ee_new entry */
				if((ee_new = read_package_entry(ps, q_u, r_u, &entry)) == NULL) {
					SAFE_FREE(buffer);
					return WERR_NOMEM;
				}
				/* Now see if there is enough room to add */
				if(r_u->num_bytes_in_resp + ee_new->record.length > q_u->max_read_size) {
					r_u->bytes_in_next_record = ee_new->record.length;
					/* response would be too big to fit in client-size buffer */
					break;
				}
				add_record_to_resp(r_u, ee_new);
				ZERO_STRUCT(entry);
				eor=False;
				num_records_read = r_u->num_records - num_records_read;
				DEBUG(10, ("_eventlog_read_eventlog: read [%d] records for a total of [%d] records using [%d] bytes out of a max of [%d].\n",
					   num_records_read,
					   r_u->num_records,
					   r_u->num_bytes_in_resp,
					   q_u->max_read_size));
			}
		}
		SAFE_FREE(buffer);
	}

	return WERR_OK;
}

/********************************************************************
********************************************************************/

WERROR _eventlog_get_oldest_entry(pipes_struct *p, EVENTLOG_Q_GET_OLDEST_ENTRY *q_u, EVENTLOG_R_GET_OLDEST_ENTRY *r_u)
{
	EventlogInfo *info = find_eventlog_info_by_hnd(p, &q_u->handle);

	if ( !(get_oldest_entry_hook(info)) ) 
		return WERR_BADFILE;

	r_u->oldest_entry = info->oldest_entry;

	return WERR_OK;
}

/********************************************************************
********************************************************************/

WERROR _eventlog_get_num_records(pipes_struct *p, EVENTLOG_Q_GET_NUM_RECORDS *q_u, EVENTLOG_R_GET_NUM_RECORDS *r_u)
{
	EventlogInfo *info = find_eventlog_info_by_hnd(p, &q_u->handle);

	if ( !(get_num_records_hook(info)) )
		return WERR_BADFILE;

	r_u->num_records = info->num_records;

	return WERR_OK;
}

