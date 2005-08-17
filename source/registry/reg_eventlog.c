/* 
 *  Unix SMB/CIFS implementation.
 *  Virtual Windows Registry Layer
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

/**********************************************************************
 handle enumeration of values AT KEY_EVENTLOG
*********************************************************************/
 
static int eventlog_topkey_values( char *key, REGVAL_CTR *val )
{
	int 		num_values = 0;
	char		*keystr, *key2 = NULL;
	char		*base, *new_path;
	fstring		evtlogname; 
	UNISTR2		data;
	uint32		uiDisplayNameId, uiMaxSize;
    
	/* 
	 *  TODO - callout to get these values...
	 */
    
	if ( !key ) 
		return 0;

	key2 = SMB_STRDUP( key );
	keystr = key2;
	reg_split_path( keystr, &base, &new_path );
	
	uiDisplayNameId = 0x00000100;
	uiMaxSize=        0x00080000;
	
	fstrcpy( evtlogname, base );
	DEBUG(10,("eventlog_topkey_values: subkey root=> [%s] subkey path=>[%s]\n", base,new_path));
	
	if ( !new_path ) {
		uiDisplayNameId = 0x01;
		regval_ctr_addvalue( val, "ErrorControl",    REG_DWORD, (char*)&uiDisplayNameId,       sizeof(uint32) ); 
	    
		init_unistr2( &data, "EventLog", UNI_STR_TERMINATE);
		regval_ctr_addvalue( val, "DisplayName",             REG_SZ, (char*)data.buffer, data.uni_str_len*sizeof(uint16) );
	    
		num_values = regval_ctr_numvals( val );	
	}
    
	SAFE_FREE( key2 ); 

	return num_values;
}

/**********************************************************************
 handle enumeration of values below KEY_EVENTLOG\<Eventlog>
*********************************************************************/
 
static int eventlog_subkey_values( char *key, REGVAL_CTR *val )
{
	int 		num_values = 0;
	char     	*keystr, *key2;
	char		*base, *new_path;
	fstring    	evtlogname; 
	UNISTR2    	data;
	uint32      	uiDisplayNameId, uiMaxSize, uiRetention;
    
	if ( !key ) 
		return 0;
    
	key2 = SMB_STRDUP( key );
	keystr = key2;
	reg_split_path( keystr, &base, &new_path );
    
	uiDisplayNameId = 0x00000100;
	
	/* MaxSize is limited to 0xFFFF0000 (UINT_MAX - USHRT_MAX) as per MSDN documentation */
	
	uiMaxSize=        0x00080000;
	
	/* records in the samba log are not overwritten (default) */
	
	uiRetention =     0x93A80;
    
	fstrcpy( evtlogname, base );
	DEBUG(10,("eventlog_subpath_values: eventlogname [%s]\n", base));
	DEBUG(10,("eventlog_subpath_values: new_path [%s]\n", new_path));
	
	if ( !new_path ) {
		regval_ctr_addvalue( val, "MaxSize",          REG_DWORD, (char*)&uiMaxSize, sizeof(uint32));
		regval_ctr_addvalue( val, "Retention",  REG_DWORD, (char *)&uiRetention, sizeof(uint32));
		
		init_unistr2( &data, base, UNI_STR_TERMINATE);
		regval_ctr_addvalue( val, "PrimaryModule",         REG_SZ, (char*)data.buffer, data.uni_str_len*sizeof(uint16) );
	
		init_unistr2( &data, base, UNI_STR_TERMINATE);
		regval_ctr_addvalue( val, "Sources",          REG_MULTI_SZ, (char*)data.buffer, data.uni_str_len*sizeof(uint16) );
	
		num_values = regval_ctr_numvals( val );	
	} else {
		uiDisplayNameId = 0x07;
		regval_ctr_addvalue( val, "CategoryCount",    REG_DWORD, (char*)&uiDisplayNameId,       sizeof(uint32) ); 
	
		init_unistr2( &data, "%SystemRoot%\\system32\\eventlog.dll", UNI_STR_TERMINATE);
		regval_ctr_addvalue( val, "CategoryMessageFile", REG_EXPAND_SZ, (char*)data.buffer, data.uni_str_len*sizeof(uint16) );
	
		num_values = regval_ctr_numvals( val );	
	
		num_values = 0;
	}
    
	SAFE_FREE( key2 ); 
	return num_values;
}


/**********************************************************************
 It is safe to assume that every registry path passed into on of 
 the exported functions here begins with KEY_EVENTLOG else
 these functions would have never been called.  This is a small utility
 function to strip the beginning of the path and make a copy that the 
 caller can modify.  Note that the caller is responsible for releasing
 the memory allocated here.
**********************************************************************/

static char* trim_eventlog_reg_path( const char *path )
{
	const char *p;
	uint16 key_len = strlen(KEY_EVENTLOG);
	
	/* sanity check...this really should never be True.  */
	
	if ( strlen(path) < key_len ) {
		DEBUG(0,("trim_reg_path: Registry path too short! [%s]\n", path));

		return NULL;
	}
	
	p = path + strlen( KEY_EVENTLOG );
	
	if ( *p == '\\' )
		p++;
	
	if ( *p )
		return SMB_STRDUP(p);

	return NULL;
}

/**********************************************************************
 Enumerate registry subkey names given a registry path.  
 Caller is responsible for freeing memory to **subkeys
*********************************************************************/

int eventlog_subkey_info( const char *key, REGSUBKEY_CTR *subkey_ctr )
{
	char 		*path;
	BOOL       	top_level = False;
	const char	**evtlog_list = lp_eventlog_list();
    
	path = trim_eventlog_reg_path( key );
	
	DEBUG(10,("eventlog_subkey_info: entire key => [%s], subkey => [%s]\n", 
		key, path));
    
	if ( !path )
		top_level = True;
    
	if ( top_level ) { 
	
		DEBUG(10,("eventlog_subkey_info: Adding eventlog subkeys from smb.conf\n"));	
	
		if ( !evtlog_list ) 
			return 0;

		for ( /* nothing */; *evtlog_list; evtlog_list++ ) 
			regsubkey_ctr_addkey( subkey_ctr, *evtlog_list);

		return regsubkey_ctr_numkeys( subkey_ctr );
	} else {
		/* if we get <logname>/<logname> then we don't add anymore */

	 	if (strchr(path,'\\')) {
	 		DEBUG(10,("eventlog_subkey_info: Not adding subkey to %s\n",path));	
	 		return 0;
	 	}

		/* add in a subkey with the same name as the eventlog... */

		DEBUG(10,("eventlog_subkey_info: Looking to add eventlog subkey to %s\n",path));	

		/* look for a match */

		evtlog_list = lp_eventlog_list(); 

		if ( !evtlog_list )
			return -1; 

		for ( /* nothing */; *evtlog_list; evtlog_list++ ) { 
			if ( strequal(path,*evtlog_list) ) {
				regsubkey_ctr_addkey( subkey_ctr, path);
				return regsubkey_ctr_numkeys( subkey_ctr );
			}
		}
	}


	
	SAFE_FREE( path );

	return -1;
}

/**********************************************************************
 Enumerate registry values given a registry path.  
 Caller is responsible for freeing memory 
*********************************************************************/

static int eventlog_value_info( const char *key, REGVAL_CTR *val )
{
	char 		*path;
	BOOL		top_level = False;
	int		num_values = 0;
	
	DEBUG(10,("eventlog_value_info: key=>[%s]\n", key));
	
	path = trim_eventlog_reg_path( key );
	
	/* check to see if we are dealing with the top level key */
	
	if ( !path )
		top_level = True;
		
	if ( top_level ) {
		num_values = eventlog_topkey_values(path,val);
	} else {
		DEBUG(10,("eventlog_value_info: SUBkey=>[%s]\n", path));
		num_values = eventlog_subkey_values(path,val);
	}
	
	return num_values;
}

/**********************************************************************
*********************************************************************/

static BOOL eventlog_store_subkey( const char *key, REGSUBKEY_CTR *subkeys )
{
        DEBUG(10,("eventlog_store_subkey: key is [%s] \n",key));
	
	return False;
}

/**********************************************************************
 Allow storing of particular values related to eventlog operation. 
 Right now these are Retention and Maxsize.
*********************************************************************/

static BOOL eventlog_store_value( const char *key, REGVAL_CTR *val )
{
	const char *evtlog_key;
	const char **evtlog_list;
	uint32  davalue;
	BOOL found = False;

	DEBUG(10,("eventlog_store_value: key is [%s] \n", key));
	
	/* We care about storing eventlog parameters that are off 
	   of the key in the form of KEY_EVENTLOG\<Eventlog_name> */
	
	evtlog_key = key + ( strlen(KEY_EVENTLOG) + 1 );
	evtlog_list = lp_eventlog_list();

	for ( /* nothing */; !found && *evtlog_list; evtlog_list++ ) {
	
		if ( !strequal(evtlog_key,*evtlog_list) )
			continue;
			
		found = True;
		
		DEBUG(10,("eventlog_store_value: matched subkey name [%s]\n",
			evtlog_key));

		/* now see if it's one of the things we care about ! */
			
		if ( regval_ctr_numvals(val) != 1 ) {
			DEBUG(10,("eventlog_store_value: More than one value to be stored! [%d]\n",
				regval_ctr_numvals(val)));
			return True;
		}
			
		DEBUG(10,("eventlog_store_value: name of value is [%s]\n",
			val->values[0]->valuename));
				
		if ( strequal(val->values[0]->valuename,"Retention")
			||  strequal(val->values[0]->valuename,"MaxSize") ) 
		{

			DEBUG(10,("eventlog_store_value: value matched, let's store it [%s]\n",
				val->values[0]->valuename));
				
			if (val->values[0]->type != REG_DWORD) {
				DEBUG(10,("eventlog_store_value: value is not a REG_DWORD!\n"));
				break;
			}
			
			memcpy(&davalue,val->values[0]->data_p,sizeof(uint32));
			
			DEBUG(10,("eventlog_store_value: value name [%s] matched, storing value type [%d], "
				"value length [%d], value itself (as dword) [%x]\n",
				  val->values[0]->valuename, val->values[0]->type,
				  val->values[0]->size, davalue));
				  
			write_evtlog_uint32_reg_value(evtlog_key, val->values[0]->valuename, davalue);
					
			/* Now inform the external eventlog machinery that 
			   there's something new...
			   all values needed are pulled by the routine... */
				   
			control_eventlog_hook(evtlog_key);
		}
	}
	
	return True;
}

/******************************************************************** 
 Table of function pointers for accessing eventlog data
 *******************************************************************/
 
REGISTRY_OPS eventlog_ops = {
	eventlog_subkey_info,
	eventlog_value_info,
	eventlog_store_subkey,
	eventlog_store_value,
	NULL
};
