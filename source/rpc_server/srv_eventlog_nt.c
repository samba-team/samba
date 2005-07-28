/* 
 *  Unix SMB/CIFS implementation.
 *  RPC Pipe client / server routines
 *  Copyright (C) Marcin Krzysztof Porwit    2005.
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

#define EVENTLOG_VERSION_V1 1 /* Will there be more? */
static TDB_CONTEXT *evtlog_tdb; /* used for eventlog parameter tdb file */

typedef struct eventlog_info
{
	/* for use by the \PIPE\eventlog policy */
	fstring source_log_file_name;
	fstring source_server_name;
	fstring handle_string;
	uint32 num_records;
	uint32 oldest_entry;
	uint32 active_entry;
	uint32 flags;
} Eventlog_info;


BOOL copy_tdb_uint32_value_to_new_tdb(TDB_CONTEXT *new_tdb, TDB_CONTEXT *tdb, char *vname, uint32 dft)
{
	uint32   data_value;
	pstring  u_vname;
	BOOL rval;
	if (!tdb || !new_tdb || !vname ) 
	{
		return False;
	}
	DEBUG(10,("copy_tdb_uint32_value_to_new_tdb: Copying item %s, default if not found %x\n",vname,dft));
	pstrcpy(u_vname, vname);
	/* NORMALIZE */
	strupper_m(u_vname);
    
	tdb_lock_bystring(tdb, u_vname, 0);
	rval= tdb_fetch_uint32(tdb, u_vname ,&data_value);
	DEBUG(10,("copy_tdb_uint32_value_to_new_tdb: rval is %x\n",rval));
    
	if (!rval) 
	{
		DEBUG(10,("copy_tdb_uint32_value_to_new_tdb: Couldn't read [%s] value default will be %x\n",u_vname, dft));
		data_value = dft;
	}
	tdb_unlock_bystring(tdb, u_vname);
    
	tdb_lock_bystring(new_tdb, u_vname, 0);
	DEBUG(10,("copy_tdb_uint32_value_to_new_tdb: Copying item %s, value is %x\n",u_vname, data_value));
    
	tdb_store_uint32(new_tdb, u_vname,data_value);
	tdb_unlock_bystring(new_tdb, u_vname);
	return True;
}
 
/***************************************************************************
  Write an entry (presumably coming from a registry write) that has an eventlog
  parameter to the eventlog tdb. 

  After this call, it's probably a good thing to update_eventlog_external to inform
  any supporting machinery that a parameter changed.

****************************************************************************/
BOOL write_evtlog_uint32_reg_value(char *evtlogname, char *vname, uint32 davalue)
{
	char evt_keyname[255];
	const char **evtlog_list;
    
	if (!evtlog_tdb) return False;
	if (!evtlogname) return False;
	if (!*evtlogname) return False;
	if (!vname) return False;
	if (!*vname) return False;
    
	/* make sure that we care about the particular eventlog name -- no bogus filling up of the tdb */
    
	evtlog_list = lp_eventlog_list();
    
	if (!evtlog_list) return False;
	while (*evtlog_list) 
	{
		if (0 == StrCaseCmp(evtlogname,*evtlog_list)) break;
		evtlog_list++;
	}
	if (!*evtlog_list) 
	{
		DEBUG(0,("write_evtlog_uint32_reg_value: We don't care about eventlogs named %s\n",evtlogname));
		return False;
	}
	/* the eventlog name is okay, but we should be checking the values that we're keeping at a higher level */
	safe_strcpy(evt_keyname,evtlogname,sizeof(evt_keyname)-1);
	safe_strcat(evt_keyname,"/",sizeof(evt_keyname)-1);
	safe_strcat(evt_keyname,vname, sizeof(evt_keyname)-1);
    
	/* NORMALIZE  */
	strupper_m(evt_keyname);
    
	tdb_lock_bystring(evtlog_tdb, evt_keyname, 0);
	DEBUG(10,("write_evtlog_uint32_reg_value: Storing value for [%s], value is %x\n",evt_keyname, davalue));
	tdb_store_uint32(evtlog_tdb, evt_keyname,davalue);
	tdb_unlock_bystring(evtlog_tdb, evt_keyname);
	return True;
}

/***************************************************************************
  Read a parameter from the eventlog_param tdb relevant to eventlogs.

****************************************************************************/
BOOL read_evtlog_uint32_reg_value(char *evtlogname, char *vname, uint32 *davalue)
{
	char evt_keyname[255];
	const char **evtlog_list;
	uint32 l_davalue;
	int    rc;
    
	if (!evtlog_tdb) return False;
	if (!evtlogname) return False;
	if (!*evtlogname) return False;
	if (!vname) return False;
	if (!*vname) return False;
    
	evtlog_list = lp_eventlog_list();
	if (!evtlog_list) return False;
    
	while (*evtlog_list) 
	{
		if (0 == StrCaseCmp(evtlogname,*evtlog_list)) break;
		evtlog_list++;
	}
	if (!*evtlog_list) 
	{
		DEBUG(0,("read_evtlog_uint32_reg_value: We don't care about eventlogs named %s\n",evtlogname));
		return False;
	}
	/* the eventlog name is okay, but we should be checking the values that we're keeping at a higher level */
	safe_strcpy(evt_keyname,evtlogname,sizeof(evt_keyname)-1);
	safe_strcat(evt_keyname,"/",sizeof(evt_keyname)-1);
	safe_strcat(evt_keyname,vname, sizeof(evt_keyname)-1);
    
	/* NORMALIZE  */
	strupper_m(evt_keyname);
    
	tdb_lock_bystring(evtlog_tdb, evt_keyname, 0);
    
	rc = tdb_fetch_uint32(evtlog_tdb, evt_keyname,&l_davalue);
	if (-1 != rc) 
	{
		*davalue = l_davalue;
		DEBUG(10,("read_evtlog_uint32_reg_value: Read value for [%s], value is %x\n",evt_keyname, *davalue));
	} 
	else 
	{
		DEBUG(10,("read_evtlog_uint32_reg_value: Read value for [%s], VALUE NOT FOUND\n",evt_keyname));
	}
    
	tdb_unlock_bystring(evtlog_tdb, evt_keyname);
	return True;
}

/***************************************************************************
  Prune entries in smb.conf to only the entries that we care about -- 
    take the currently existing TDB context -- filter to the entries that we have
    read from smb.conf, write them to new TDB, close/unlink the old, rename new to old.

****************************************************************************/

static BOOL cleanup_eventlog_parameters(TDB_CONTEXT *levtlog_tdb)
{
	TDB_CONTEXT *new_tdb;
	const char *vstring = "INFO/version";
	char  evtlogname[255];
	const char        **evtlog_list;
	pstring  old_tdbfile,new_tdbfile;
    
	pstrcpy(new_tdbfile, lock_path("eventlog_params.tdb.new")); 
	pstrcpy(old_tdbfile, lock_path("eventlog_params.tdb")); 
    
	unlink(new_tdbfile); /* remove any existing file */
    
	new_tdb = tdb_open_log(new_tdbfile, 0, TDB_DEFAULT, O_RDWR|O_CREAT, 0600);
	if (!new_tdb) 
	{
		DEBUG(0,("Failed to create new eventlog parameters db\n"));
		return False;
	}
	/* write initial information out */
	tdb_lock_bystring(new_tdb, vstring, 0);
	tdb_store_uint32(new_tdb, vstring, EVENTLOG_VERSION_V1);
	tdb_unlock_bystring(new_tdb, vstring);
    
	/* for each eventlog that we have, find info related to it and copy to the new DB */
	evtlog_list = lp_eventlog_list();
	while (*evtlog_list) 
	{
		DEBUG(10,("cleanup_eventlog_parameters: Cleaning up =>[%s]\n",*evtlog_list));	
	
		safe_strcpy(evtlogname,(*evtlog_list),sizeof(evtlogname)-1);
		safe_strcat(evtlogname,"/RETENTION",sizeof(evtlogname)-1);
		copy_tdb_uint32_value_to_new_tdb(new_tdb,levtlog_tdb,evtlogname,0x93A80);
		safe_strcpy(evtlogname,*evtlog_list,sizeof(evtlogname)-1);
		safe_strcat(evtlogname,"/MAXSIZE",sizeof(evtlogname)-1);
		copy_tdb_uint32_value_to_new_tdb(new_tdb,levtlog_tdb,evtlogname,0x80000);
		evtlog_list++;
	}  
    
	DEBUG(10,("cleanup_eventlog_parameters: removing current TDB\n"));
    
	/* close current TDB */
	tdb_unlockall(evtlog_tdb);
	tdb_close(evtlog_tdb);
    
	/* close current new_tdb */
	tdb_unlockall(new_tdb);
	tdb_close(new_tdb);
    
	/* unlink current TDB */
	if (0 != unlink(old_tdbfile)) 
	{
		DEBUG(1,("cleanup_eventlog_parameters: unable to unlink old file %s %s\n",old_tdbfile,strerror(errno)));
	}
    
	/* rename new_tdb  */
	if (0 != rename(new_tdbfile,old_tdbfile)) 
	{
		DEBUG(1,("cleanup_eventlog_parameters: Can't rename new to old : %s\n",strerror(errno)));
	}
	DEBUG(10,("cleanup_eventlog_parameters: Renamed %s to %s : \n",new_tdbfile,old_tdbfile));
    
	evtlog_tdb = tdb_open_log(old_tdbfile, 0, TDB_DEFAULT, O_RDWR, 0600);
    
	if (!evtlog_tdb) 
	{
		DEBUG(1,("cleanup_eventlog_parameters: Can't re-open eventlog parameter db\n"));
	}
    
	return True;
}

/****************************************************************

  Inform the external eventlog machinery of default values (on startup probably)

***************************************************************/

void eventlog_refresh_external_parameters(void)
{
	const char **evtlog_list;
    
	evtlog_list = lp_eventlog_list();
	while (*evtlog_list) 
	{
		DEBUG(10,("eventlog_refresh_external_parameters: Refreshing =>[%s]\n",*evtlog_list));	
		if (!eventlog_control_eventlog( (char *)*evtlog_list)) 
		{
			DEBUG(0,("eventlog_refresh_external_parameters: failed to refresh [%s]\n",*evtlog_list));
		}
		evtlog_list++;
	}  
    
	return;
}

/****************************************************************************
 Open the eventlog parameter tdb. This code a clone of init_group_mapping.
****************************************************************************/

BOOL init_eventlog_parameters(void)
{
	const char *vstring = "INFO/version";
	uint32 vers_id;
	
	if (evtlog_tdb)
		return True;

	evtlog_tdb = tdb_open_log(lock_path("eventlog_params.tdb"), 0, TDB_DEFAULT, O_RDWR, 0600);
	if (!evtlog_tdb) 
	{
		DEBUG(0,("Failed to open eventlog parameters db\n"));
		evtlog_tdb = tdb_open_log(lock_path("eventlog_params.tdb"), 0, TDB_DEFAULT, O_RDWR|O_CREAT, 0600);
		if (!evtlog_tdb) return False;
		DEBUG(0,("Created new eventlog parameters db\n"));
	}
	if ((-1 == tdb_fetch_uint32(evtlog_tdb, vstring,&vers_id)) || (vers_id != EVENTLOG_VERSION_V1)) 
	{
		/* wrong version of DB, or db was just created */
		tdb_traverse(evtlog_tdb, tdb_traverse_delete_fn, NULL);
		tdb_store_uint32(evtlog_tdb, vstring, EVENTLOG_VERSION_V1);
	}
	tdb_unlock_bystring(evtlog_tdb, vstring);

	DEBUG(0,("Cleaning up eventlog parameters db\n"));

	cleanup_eventlog_parameters(evtlog_tdb);
	return True;
}

static void free_eventlog_info(void *ptr)
{
	struct eventlog_info *info = (struct eventlog_info *)ptr;
	memset(info->source_log_file_name, '0', sizeof(*(info->source_log_file_name)));
	memset(info->source_server_name, '0', sizeof(*(info->source_server_name)));
	memset(info->handle_string, '0', sizeof(*(info->handle_string)));
	memset(info, 0, sizeof(*(info)));
	SAFE_FREE(info);
}


static Eventlog_info *find_eventlog_info_by_hnd(pipes_struct *p,
						POLICY_HND *handle)
{
	Eventlog_info *info = NULL;
    
	if(!(find_policy_by_hnd(p,handle,(void **)&info)))
	{
		DEBUG(2,("find_eventlog_info_by_hnd: eventlog not found.\n"));
	}

	return info;
}

void policy_handle_to_string(POLICY_HND *handle, fstring *dest)
{
	memset(dest, 0, sizeof(*dest));
	snprintf((char *)dest, sizeof(*dest), "%08X-%08X-%04X-%04X-%02X%02X%02X%02X%02X",
		 handle->data1,
		 handle->data2,
		 handle->data3,
		 handle->data4,
		 handle->data5[0],
		 handle->data5[1],
		 handle->data5[2],
		 handle->data5[3],
		 handle->data5[4]);
}

/**
 * Callout to control the specified event log - passing out only the MaxSize and Retention values, along with eventlog name
 * 
 *    uses smbrun...
 *     INPUT: <control_cmd> <log name> <retention> <maxsize>
 *     OUTPUT: nothing
 */
BOOL eventlog_control_eventlog(char *evtlogname)
{
	char *cmd = lp_eventlog_control_cmd();
	pstring command;
	pstring v_name;
	int ret;
	int fd = -1;
	uint32 uiRetention;
	uint32 uiMaxSize;

	if(cmd == NULL || strlen(cmd) == 0)
	{
		DEBUG(0, ("eventlog_control_eventlog: Must define an \"eventlog control command\" entry in the config.\n"));
		return False;
	}

	uiRetention = 0x93A80;
	uiMaxSize = 0x80000;  // defaults
	//evtlogname=info->source_log_file_name;

	pstrcpy(v_name,"Retention");

	if (!read_evtlog_uint32_reg_value(evtlogname, v_name, &uiRetention)) {
		DEBUG(0, ("eventlog_control_eventlog: Warning - can't read Retention for eventlog %s, using default.\n",evtlogname));
	}

	pstrcpy(v_name,"MaxSize");
	if (!read_evtlog_uint32_reg_value(evtlogname, v_name, &uiMaxSize)) {
		DEBUG(0, ("eventlog_control_eventlog: Warning - can't read MaxSize for eventlog %s, using default.\n",evtlogname));
	}

	memset(command, 0, sizeof(command));
	slprintf(command, sizeof(command)-1, "%s \"%s\" %u %u",
		 cmd,
		 evtlogname,
		 uiRetention,
		 uiMaxSize);

	DEBUG(10, ("eventlog_control_eventlog: Running [%s]\n", command));
	ret = smbrun(command, &fd);
	DEBUGADD(10, ("returned [%d]\n", ret));

	if(ret != 0)
	{
		DEBUG(10, ("eventlog_control_eventlog: Command returned  [%d]\n", ret));
		if(fd != -1)
			close(fd);
		return False;
	}

	close(fd);
	return False;
}


/**
 * Callout to open the specified event log
 * 
 *   smbrun calling convention --
 *     INPUT: <open_cmd> <log name> <policy handle>
 *     OUTPUT: the string "SUCCESS" if the command succeeded
 *             no such string if there was a failure.
 */
static BOOL _eventlog_open_eventlog_hook(Eventlog_info *info)
{
	char *cmd = lp_eventlog_open_cmd();
	char **qlines;
	pstring command;
	int numlines = 0;
	int ret;
	int fd = -1;

	if(cmd == NULL || strlen(cmd) == 0)
	{
		DEBUG(0, ("Must define an \"eventlog open command\" entry in the config.\n"));
		return False;
	}

	memset(command, 0, sizeof(command));
	slprintf(command, sizeof(command)-1, "%s \"%s\" \"%s\"",
		 cmd,
		 info->source_log_file_name,
		 info->handle_string);

	DEBUG(10, ("Running [%s]\n", command));
	ret = smbrun(command, &fd);
	DEBUGADD(10, ("returned [%d]\n", ret));

	if(ret != 0)
	{
		if(fd != -1)
			close(fd);
		return False;
	}

	qlines = fd_lines_load(fd, &numlines);
	DEBUGADD(10, ("Lines returned = [%d]\n", numlines));
	close(fd);

	if(numlines)
	{
		DEBUGADD(10, ("Line[0] = [%s]\n", qlines[0]));
		if(0 == strncmp(qlines[0], "SUCCESS", strlen("SUCCESS")))
		{
			DEBUGADD(10, ("Able to open [%s].\n", info->source_log_file_name));
			file_lines_free(qlines);
			return True;
		}
	}

	file_lines_free(qlines);
	return False;
}

WERROR _eventlog_open_eventlog(pipes_struct *p,
			       EVENTLOG_Q_OPEN_EVENTLOG *q_u,
			       EVENTLOG_R_OPEN_EVENTLOG *r_u)
{
	Eventlog_info *info = NULL;
    
	if(!q_u || !r_u)
		return WERR_NOMEM;
    
	if((info = SMB_MALLOC_P(Eventlog_info)) == NULL)
		return WERR_NOMEM;
    
	ZERO_STRUCTP(info);

	if(q_u->servername_ptr != 0)
	{
		unistr2_to_ascii(info->source_server_name, &(q_u->servername), sizeof(info->source_server_name));
	}
	else
	{
		/* if servername == NULL, use the local computer */
		fstrcpy(info->source_server_name, global_myname());
	}
	DEBUG(10, ("_eventlog_open_eventlog: Using [%s] as the server name.\n", info->source_server_name));

	if(q_u->sourcename_ptr != 0)
	{
		unistr2_to_ascii(info->source_log_file_name, &(q_u->sourcename), sizeof(info->source_log_file_name));
	}
	else
	{
		/* if sourcename == NULL, default to "Application" log */
		fstrcpy(info->source_log_file_name, "Application");
	}
	DEBUG(10, ("_eventlog_open_eventlog: Using [%s] as the source log file.\n", info->source_log_file_name));

	if(!create_policy_hnd(p, &(r_u->handle), free_eventlog_info, (void *)info))
	{
		free_eventlog_info(info);
		return WERR_NOMEM;
	}
	
	policy_handle_to_string(&r_u->handle, &info->handle_string);

	if(!(_eventlog_open_eventlog_hook(info)))
	{
		close_policy_hnd(p, &r_u->handle);
		return WERR_BADFILE;
	}
	
	return WERR_OK;
}
/**
 * Callout to get the number of records in the specified event log
 * 
 *   smbrun calling convention --
 *     INPUT: <get_num_records_cmd> <log name> <policy handle>
 *     OUTPUT: A single line with a single integer containing the number of
 *             entries in the log. If there are no entries in the log, return 0.
 */
static BOOL _eventlog_get_num_records_hook(Eventlog_info *info)
{
	char *cmd = lp_eventlog_num_records_cmd();
	char **qlines;
	pstring command;
	int numlines = 0;
	int ret;
	int fd = -1;

	if(cmd == NULL || strlen(cmd) == 0)
	{
		DEBUG(0, ("Must define an \"eventlog num records command\" entry in the config.\n"));
		return False;
	}

	memset(command, 0, sizeof(command));
	slprintf(command, sizeof(command)-1, "%s \"%s\" \"%s\"", 
		 cmd,
		 info->source_log_file_name,
		 info->handle_string);

	DEBUG(10, ("Running [%s]\n", command));
	ret = smbrun(command, &fd);
	DEBUGADD(10, ("returned [%d]\n", ret));

	if(ret != 0)
	{
		if(fd != -1)
			close(fd);
		return False;
	}

	qlines = fd_lines_load(fd, &numlines);
	DEBUGADD(10, ("Lines returned = [%d]\n", numlines));
	close(fd);

	if(numlines)
	{
		DEBUGADD(10, ("Line[0] = [%s]\n", qlines[0]));
		sscanf(qlines[0], "%d", &(info->num_records));
		file_lines_free(qlines);
		return True;
	}

	file_lines_free(qlines);
	return False;
}

WERROR _eventlog_get_num_records(pipes_struct *p,
				 EVENTLOG_Q_GET_NUM_RECORDS *q_u,
				 EVENTLOG_R_GET_NUM_RECORDS *r_u)
{
	Eventlog_info *info = NULL;
	POLICY_HND *handle = NULL;

	if(!q_u || !r_u)
		return WERR_NOMEM;

	handle = &(q_u->handle);
	info = find_eventlog_info_by_hnd(p, handle);

	if(!(_eventlog_get_num_records_hook(info)))
		return WERR_BADFILE;

	r_u->num_records = info->num_records;

	return WERR_OK;
}
/**
 * Callout to find the oldest record in the log
 * 
 *   smbrun calling convention --
 *     INPUT: <oldest_entry_cmd> <log name> <policy handle>
 *     OUTPUT: If there are entries in the event log, the index of the
 *             oldest entry. Must be 1 or greater.
 *             If there are no entries in the log, returns a 0
 */
static BOOL _eventlog_get_oldest_entry_hook(Eventlog_info *info)
{
	char *cmd = lp_eventlog_oldest_record_cmd();
	char **qlines;
	pstring command;
	int numlines = 0;
	int ret;
	int fd = -1;

	if(cmd == NULL || strlen(cmd) == 0)
	{
		DEBUG(0, ("Must define an \"eventlog oldest record command\" entry in the config.\n"));
		return False;
	}

	memset(command, 0, sizeof(command));
	slprintf(command, sizeof(command)-1, "%s \"%s\" \"%s\"", 
		 cmd,
		 info->source_log_file_name,
		 info->handle_string);

	DEBUG(10, ("Running [%s]\n", command));
	ret = smbrun(command, &fd);
	DEBUGADD(10, ("returned [%d]\n", ret));

	if(ret != 0)
	{
		if(fd != -1)
			close(fd);
		return False;
	}

	qlines = fd_lines_load(fd, &numlines);
	DEBUGADD(10, ("Lines returned = [%d]\n", numlines));
	close(fd);

	if(numlines)
	{
		DEBUGADD(10, ("Line[0] = [%s]\n", qlines[0]));
		sscanf(qlines[0], "%d", &(info->oldest_entry));
		file_lines_free(qlines);
		return True;
	}

	file_lines_free(qlines);
	return False;
}

WERROR _eventlog_get_oldest_entry(pipes_struct *p,
				  EVENTLOG_Q_GET_OLDEST_ENTRY *q_u,
				  EVENTLOG_R_GET_OLDEST_ENTRY *r_u)
{
	Eventlog_info *info = NULL;
	POLICY_HND *handle = NULL;

	if(!q_u || !r_u)
		return WERR_NOMEM;

	handle = &(q_u->handle);
	info = find_eventlog_info_by_hnd(p, handle);

	if(!(_eventlog_get_oldest_entry_hook(info)))
		return WERR_BADFILE;

	r_u->oldest_entry = info->oldest_entry;

	return WERR_OK;
}

/**
 * Callout to close the specified event log
 * 
 *   smbrun calling convention --
 *     INPUT: <close_cmd> <log name> <policy handle>
 *     OUTPUT: the string "SUCCESS" if the command succeeded
 *             no such string if there was a failure.
 */
static BOOL _eventlog_close_eventlog_hook(Eventlog_info *info)
{
	char *cmd = lp_eventlog_close_cmd();
	char **qlines;
	pstring command;
	int numlines = 0;
	int ret;
	int fd = -1;

	if(cmd == NULL || strlen(cmd) == 0)
	{
		DEBUG(0, ("Must define an \"eventlog close command\" entry in the config.\n"));
		return False;
	}

	memset(command, 0, sizeof(command));
	slprintf(command, sizeof(command)-1, "%s \"%s\" \"%s\"", 
		 cmd, 
		 info->source_log_file_name, 
		 info->handle_string);

	DEBUG(10, ("Running [%s]\n", command));
	ret = smbrun(command, &fd);
	DEBUGADD(10, ("returned [%d]\n", ret));

	if(ret != 0)
	{
		if(fd != -1)
			close(fd);
		return False;
	}

	qlines = fd_lines_load(fd, &numlines);
	DEBUGADD(10, ("Lines returned = [%d]\n", numlines));
	close(fd);

	if(numlines)
	{
		DEBUGADD(10, ("Line[0] = [%s]\n", qlines[0]));
		if(0 == strncmp(qlines[0], "SUCCESS", strlen("SUCCESS")))
		{
			DEBUGADD(10, ("Able to close [%s].\n", info->source_log_file_name));
			file_lines_free(qlines);
			return True;
		}
	}

	file_lines_free(qlines);
	return False;
}

WERROR _eventlog_close_eventlog(pipes_struct *p,
				EVENTLOG_Q_CLOSE_EVENTLOG *q_u,
				EVENTLOG_R_CLOSE_EVENTLOG *r_u)
{
	Eventlog_info *info = NULL;
	POLICY_HND *handle;

	if(!q_u || !r_u)
		return WERR_NOMEM;

	handle = &(q_u->handle);
    
	info = find_eventlog_info_by_hnd(p, handle);
	if(!(_eventlog_close_eventlog_hook(info)))
		return WERR_BADFILE;

	if(!(close_policy_hnd(p, handle)))
	{
		/* WERR_NOMEM is probably not the correct error, but until I figure out a better
		   one it will have to do */
		return WERR_NOMEM;
	}

	return WERR_OK;
}

static BOOL _eventlog_read_parse_line(char *line, Eventlog_entry *entry, BOOL *eor)
{
	char *start = NULL, *stop = NULL;
	pstring temp;
	int temp_len = 0, i;
 
	start = line;

	/* empty line signyfiying record delimeter, or we're at the end of the buffer */
	if(start == NULL || strlen(start) == 0)
	{
		DEBUG(6, ("_eventlog_read_parse_line: found end-of-record indicator.\n"));
		*eor = True;
		return True;
	}
	if(!(stop = strchr(line, ':')))
		return False;
    
	DEBUG(6, ("_eventlog_read_parse_line: trying to parse [%s].\n", line));

	if(0 == strncmp(start, "LEN", stop - start))
	{
		/* This will get recomputed later anyway -- probably not necessary */
		entry->record.length = atoi(stop + 1);
	}
	else if(0 == strncmp(start, "RS1", stop - start))
	{
		/* For now all these reserved entries seem to have the same value,
		   which can be hardcoded to int(1699505740) for now */
		entry->record.reserved1 = atoi(stop + 1);
	}
	else if(0 == strncmp(start, "RCN", stop - start))
	{
		entry->record.record_number = atoi(stop + 1);
	}
	else if(0 == strncmp(start, "TMG", stop - start))
	{
		entry->record.time_generated = atoi(stop + 1);
	}
	else if(0 == strncmp(start, "TMW", stop - start))
	{
		entry->record.time_written = atoi(stop + 1);
	}
	else if(0 == strncmp(start, "EID", stop - start))
	{
		entry->record.event_id = atoi(stop + 1);
	}
	else if(0 == strncmp(start, "ETP", stop - start))
	{
		if(strstr(start, "ERROR"))
		{
			entry->record.event_type = EVENTLOG_ERROR_TYPE;
		}
		else if(strstr(start, "WARNING"))
		{
			entry->record.event_type = EVENTLOG_WARNING_TYPE;
		}
		else if(strstr(start, "INFO"))
		{
			entry->record.event_type = EVENTLOG_INFORMATION_TYPE;
		}
		else if(strstr(start, "AUDIT_SUCCESS"))
		{
			entry->record.event_type = EVENTLOG_AUDIT_SUCCESS;
		}
		else if(strstr(start, "AUDIT_FAILURE"))
		{
			entry->record.event_type = EVENTLOG_AUDIT_FAILURE;
		}
		else if(strstr(start, "SUCCESS"))
		{
			entry->record.event_type = EVENTLOG_SUCCESS;
		}
		else
		{
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
	else if(0 == strncmp(start, "ECT", stop - start))
	{
		entry->record.event_category = atoi(stop + 1);
	}
	else if(0 == strncmp(start, "RS2", stop - start))
	{
		entry->record.reserved2 = atoi(stop + 1);
	}
	else if(0 == strncmp(start, "CRN", stop - start))
	{
		entry->record.closing_record_number = atoi(stop + 1);
	}
	else if(0 == strncmp(start, "USL", stop - start))
	{
		entry->record.user_sid_length = atoi(stop + 1);
	}
	else if(0 == strncmp(start, "SRC", stop - start))
	{
		memset(temp, 0, sizeof(temp));
		stop++;
		while(isspace(stop[0]))
			stop++;
		temp_len = strlen(stop);
		strncpy(temp, stop, temp_len);
		rpcstr_push((void *)(entry->data_record.source_name), temp, 
			    sizeof(entry->data_record.source_name), STR_TERMINATE);
		entry->data_record.source_name_len = (strlen_w(entry->data_record.source_name)* 2) + 2;
	}
	else if(0 == strncmp(start, "SRN", stop - start))
	{
		memset(temp, 0, sizeof(temp));
		stop++;
		while(isspace(stop[0]))
			stop++;
		temp_len = strlen(stop);
		strncpy(temp, stop, temp_len);
		rpcstr_push((void *)(entry->data_record.computer_name), temp,
			    sizeof(entry->data_record.computer_name), STR_TERMINATE);
		entry->data_record.computer_name_len = (strlen_w(entry->data_record.computer_name)* 2) + 2;
	}
	else if(0 == strncmp(start, "SID", stop - start))
	{
		memset(temp, 0, sizeof(temp));
		stop++;
		while(isspace(stop[0]))
			stop++;
		temp_len = strlen(stop);
		strncpy(temp, stop, temp_len);
		rpcstr_push((void *)(entry->data_record.sid), temp,
			    sizeof(entry->data_record.sid), STR_TERMINATE);
		entry->record.user_sid_length = (strlen_w(entry->data_record.sid) * 2) + 2;
	}
	else if(0 == strncmp(start, "STR", stop - start))
	{
		/* skip past initial ":" */
		stop++;
		/* now skip any other leading whitespace */
		while(isspace(stop[0]))
			stop++;
		temp_len = strlen(stop);
		memset(temp, 0, sizeof(temp));
		strncpy(temp, stop, temp_len);
		rpcstr_push((void *)(entry->data_record.strings + entry->data_record.strings_len),
			    temp,
			    sizeof(entry->data_record.strings) - entry->data_record.strings_len, 
			    STR_TERMINATE);
		entry->data_record.strings_len += temp_len + 1;
		fprintf(stderr, "Dumping strings:\n");
		for(i = 0; i < entry->data_record.strings_len; i++)
		{
			fputc((char)entry->data_record.strings[i], stderr);
		}
		fprintf(stderr, "\nDone\n");
		entry->record.num_strings++;
	}
	else if(0 == strncmp(start, "DAT", stop - start))
	{
		/* Now that we're done processing the STR data, adjust the length to account for
		   unicode, then proceed with the DAT data. */
		entry->data_record.strings_len *= 2;
		/* skip past initial ":" */
		stop++;
		/* now skip any other leading whitespace */
		while(isspace(stop[0]))
			stop++;
		memset(temp, 0, sizeof(temp));
		temp_len = strlen(stop);
		strncpy(temp, stop, temp_len);
		rpcstr_push((void *)(entry->data_record.user_data), temp,
			    sizeof(entry->data_record.user_data), STR_TERMINATE);
		entry->data_record.user_data_len = (strlen_w((const smb_ucs2_t *)entry->data_record.user_data) * 2) + 2;
	}
	else
	{
		/* some other eventlog entry -- not implemented, so dropping on the floor */
		DEBUG(10, ("Unknown entry [%s]. Ignoring.\n", line));
		/* For now return true so that we can keep on parsing this mess. Eventually
		   we will return False here. */
		return True;
	}
	return True;
}
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
static BOOL _eventlog_read_eventlog_hook(Eventlog_info *info,
					 Eventlog_entry *entry, 
					 const char *direction, 
					 int starting_record, 
					 int buffer_size, 
					 BOOL *eof,
					 char ***buffer,
					 int *numlines)
{
	char *cmd = lp_eventlog_read_cmd();
	pstring command;
	int ret;
	int fd = -1;

	if(info == NULL)
		return False;

	if(cmd == NULL || strlen(cmd) == 0)
	{
		DEBUG(0, ("Must define an \"eventlog read command\" entry in the config.\n"));
		return False;
	}

	slprintf(command, sizeof(command)-1, "%s \"%s\" %s %d %d \"%s\"",
		 cmd,
		 info->source_log_file_name,
		 direction,
		 starting_record,
		 buffer_size,
		 info->handle_string);

	*numlines = 0;

	DEBUG(10, ("Running [%s]\n", command));
	ret = smbrun(command, &fd);
	DEBUGADD(10, ("returned [%d]\n", ret));

	if(ret != 0)
	{
		if(fd != -1)
			close(fd);
		return False;
	}

	*buffer = fd_lines_load(fd, numlines);
	DEBUGADD(10, ("Lines returned = [%d]\n", *numlines));
	close(fd);
    
	if(*numlines)
	{
		/*
		  for(i = 0; i < numlines; i++)
		  {
		  DEBUGADD(10, ("Line[%d] = %s\n", i, qlines[i]));
		  _eventlog_read_parse_line(qlines[i], entry);
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
	
static Eventlog_entry *_eventlog_read_package_entry(prs_struct *ps,
						    EVENTLOG_Q_READ_EVENTLOG *q_u,
						    EVENTLOG_R_READ_EVENTLOG *r_u,
						    Eventlog_entry *entry)
{
	uint8 *offset;
	Eventlog_entry *ee_new = NULL;

	ee_new = PRS_ALLOC_MEM(ps, Eventlog_entry, 1);
	if(ee_new == NULL)
		return NULL;

	entry->data_record.sid_padding = ((4 - ((entry->data_record.source_name_len 
						 + entry->data_record.computer_name_len) % 4)) %4);
	entry->data_record.data_padding = (4 - ((entry->data_record.strings_len 
						 + entry->data_record.user_data_len) % 4)) % 4;
	entry->record.length = sizeof(Eventlog_record);
	entry->record.length += entry->data_record.source_name_len;
	entry->record.length += entry->data_record.computer_name_len;
	if(entry->record.user_sid_length == 0)
	{
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
	if(entry->data == NULL)
		return NULL;
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

static BOOL _eventlog_add_record_to_resp(EVENTLOG_R_READ_EVENTLOG *r_u, Eventlog_entry *ee_new)
{
	Eventlog_entry *insert_point;

	insert_point=r_u->entry;

	if (NULL == insert_point) 
	{
		r_u->entry = ee_new;
		ee_new->next = NULL;
	} 
	else
	{
		while ((NULL != insert_point->next)) 
		{
			insert_point=insert_point->next;
		}
		ee_new->next = NULL;
		insert_point->next = ee_new;
	}
	r_u->num_records++; 
	r_u->num_bytes_in_resp += ee_new->record.length;

	return True;
}
    
WERROR _eventlog_read_eventlog(pipes_struct *p,
			       EVENTLOG_Q_READ_EVENTLOG *q_u,
			       EVENTLOG_R_READ_EVENTLOG *r_u)
{
	Eventlog_info *info = NULL;
	POLICY_HND *handle;
	Eventlog_entry entry, *ee_new;
	BOOL eof = False, eor = False;
	const char *direction = "";
	uint32 num_records_read = 0;
	prs_struct *ps;
	int numlines, i;
	char **buffer;

	if(!q_u || !r_u)
		return WERR_NOMEM;

	handle = &(q_u->handle);
	info = find_eventlog_info_by_hnd(p, handle);
	info->flags = q_u->flags;
	ps = &p->out_data.rdata;
	/* if this is the first time we're reading on this handle */
	if(info->active_entry == 0)
	{
		/* Rather than checking the EVENTLOG_SEQUENTIAL_READ/EVENTLOG_SEEK_READ flags,
		   we'll just go to the offset specified in the request, or the oldest entry
		   if no offset is specified */
		if(q_u->offset > 0)
			info->active_entry = q_u->offset;
		else
			info->active_entry = info->oldest_entry;
	}
    
	if(q_u->flags & EVENTLOG_FORWARDS_READ)
		direction = "forward";
	else if(q_u->flags & EVENTLOG_BACKWARDS_READ)
		direction = "backward";

	if(!(_eventlog_read_eventlog_hook(info, &entry, direction, info->active_entry, q_u->max_read_size, &eof, &buffer, &numlines)))
	{
		if(eof == False)
			return WERR_NOMEM;
	}
	if(numlines > 0)
	{
		ZERO_STRUCT(entry);
		for(i = 0; i < numlines; i++)
		{
			num_records_read = r_u->num_records;
			DEBUGADD(10, ("Line[%d] = [%s]\n", i, buffer[i]));
			_eventlog_read_parse_line(buffer[i], &entry, &eor);
			if(eor == True)
			{
				/* package ee_new entry */
				if((ee_new = _eventlog_read_package_entry(ps, q_u, r_u, &entry)) == NULL)
				{
					free(buffer);
					return WERR_NOMEM;
				}
				/* Now see if there is enough room to add */
				if(r_u->num_bytes_in_resp + ee_new->record.length > q_u->max_read_size)
				{
					r_u->bytes_in_next_record = ee_new->record.length;
					/* response would be too big to fit in client-size buffer */
					break;
				}
				_eventlog_add_record_to_resp(r_u, ee_new);
				ZERO_STRUCT(entry);
				eor=False;
				num_records_read = r_u->num_records - num_records_read;
				DEBUG(10, ("_eventlog_read_eventlog: read [%d] records for a total of [%d] records using [%d] bytes out of a max of [%d].\n",
					   num_records_read,
					   r_u->num_records,
					   r_u->num_bytes_in_resp,
					   q_u->max_read_size));
				/* update the active record */
				if(info->flags & EVENTLOG_FORWARDS_READ)
					info->active_entry += num_records_read;
				else if(info->flags & EVENTLOG_BACKWARDS_READ)
					info->active_entry -= num_records_read;
			}
		}
		free(buffer);
	}

	return WERR_OK;
}
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
static BOOL _eventlog_clear_eventlog_hook(Eventlog_info *info,
					  pstring backup_file_name)
{
	char *cmd = lp_eventlog_clear_cmd();
	char **qlines;
	pstring command;
	int numlines = 0;
	int ret;
	int fd = -1;

	if(cmd == NULL || strlen(cmd) == 0)
	{
		DEBUG(0, ("Must define an \"eventlog clear command\" entry in the config.\n"));
		return False;
	}

	memset(command, 0, sizeof(command));
	if(strlen(backup_file_name) > 0)
		slprintf(command, sizeof(command)-1, "%s \"%s\" \"%s\" \"%s\"",
			 cmd,
			 info->source_log_file_name,
			 backup_file_name,
			 info->handle_string);
	else
		slprintf(command, sizeof(command)-1, "%s \"%s\" \"%s\"", 
			 cmd, 
			 info->source_log_file_name, 
			 info->handle_string);

	DEBUG(10, ("Running [%s]\n", command));
	ret = smbrun(command, &fd);
	DEBUGADD(10, ("returned [%d]\n", ret));

	if(ret != 0)
	{
		if(fd != -1)
			close(fd);
		return False;
	}

	qlines = fd_lines_load(fd, &numlines);
	DEBUGADD(10, ("Lines returned = [%d]\n", numlines));
	close(fd);

	if(numlines)
	{
		DEBUGADD(10, ("Line[0] = [%s]\n", qlines[0]));
		if(0 == strncmp(qlines[0], "SUCCESS", strlen("SUCCESS")))
		{
			DEBUGADD(10, ("Able to clear [%s].\n", info->source_log_file_name));
			file_lines_free(qlines);
			return True;
		}
	}

	file_lines_free(qlines);
	return False;
}

WERROR _eventlog_clear_eventlog(pipes_struct *p,
				EVENTLOG_Q_CLEAR_EVENTLOG *q_u,
				EVENTLOG_R_CLEAR_EVENTLOG *r_u)
{
	Eventlog_info *info = NULL;
	pstring backup_file_name;
	POLICY_HND *handle = NULL;

	if(!q_u || !r_u)
		return WERR_NOMEM;

	handle = &(q_u->handle);
	info = find_eventlog_info_by_hnd(p, handle);
	memset(backup_file_name, 0, sizeof(backup_file_name));

	if(q_u->backup_file_ptr != 0)
	{
		unistr2_to_ascii(backup_file_name, &(q_u->backup_file), sizeof(backup_file_name));
		DEBUG(10, ("_eventlog_clear_eventlog: Using [%s] as the backup file name for log [%s].",
			   backup_file_name,
			   info->source_log_file_name));
	}
	else
	{
		/* if backup_file == NULL, do not back up the log before clearing it */
		DEBUG(10, ("_eventlog_clear_eventlog: clearing [%s] log without making a backup.",
			   info->source_log_file_name));
	}

	if(!(_eventlog_clear_eventlog_hook(info, backup_file_name)))
		return WERR_BADFILE;

	return WERR_OK;
}
